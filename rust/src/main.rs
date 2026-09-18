//! Experimental additive local-skill inspector.
//!
//! This binary intentionally implements only the explicit, local `inspect --skills
//! --json PATH...` vertical slice. It delegates text redaction to the released
//! Python `agent_scan.redact.redact_text` implementation in one private worker
//! process, so this supported path has the same secret-detection semantics rather
//! than a partial Rust approximation that could leak credentials.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

const BINARY_FILE_DESCRIPTION_PREFIX: &str = "Binary file. Hash: ";
const PYTHON_REDACTOR: &str = r#"
import json
import sys
from agent_scan.redact import redact_text
from agent_scan.skill_client import parse_skill_frontmatter

for raw_line in sys.stdin:
    try:
        request = json.loads(raw_line)
        # Never write an input value to stderr. A caller must receive either a
        # redacted value on stdout or a generic non-zero failure.
        if request["operation"] == "redact":
            response = {"content": redact_text(request["content"]) or ""}
        elif request["operation"] == "frontmatter":
            response = {"name": parse_skill_frontmatter(request["content"], request["path"]).name}
        else:
            sys.exit(2)
        print(json.dumps(response, ensure_ascii=False), flush=True)
    except Exception:
        sys.exit(2)
"#;

#[derive(Debug, Parser)]
#[command(
    name = "snyk-agent-scan-rust",
    version,
    about = "Experimental additive local skill inspector for Snyk Agent Scan"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect explicitly supplied local skill directories without network access.
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// Required for this experimental binary; MCP inspection is not implemented.
    #[arg(long)]
    skills: bool,

    /// Required for this experimental binary; emits the Python inspect JSON shape.
    #[arg(long)]
    json: bool,

    /// A skill directory containing SKILL.md, a SKILL.md file, or a directory of skills.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
}

#[derive(Debug, Error)]
enum ScanError {
    #[error("only `inspect --skills --json PATH...` is supported; see docs/rust-local-inspect.md")]
    UnsupportedSurface,

    #[error("invalid skill at {path}: {reason}")]
    InvalidSkill { path: String, reason: String },

    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "the Python redaction worker could not be started; set AGENT_SCAN_PYTHON to an interpreter with snyk-agent-scan installed"
    )]
    RedactorStart,

    #[error("the Python redaction worker failed; no unredacted output was emitted")]
    RedactorFailed,

    #[error("the Python redaction worker returned invalid data; no unredacted output was emitted")]
    RedactorProtocol,

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SkillFile {
    path: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct InspectedSkill {
    name: String,
    installation_path: String,
    files: Vec<SkillFile>,
    error: Option<()>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct InspectedPath {
    client: String,
    path: String,
    servers: Vec<()>,
    skills: Vec<InspectedSkill>,
    error: Option<()>,
}

struct PythonRedactor {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl PythonRedactor {
    fn start() -> Result<Self, ScanError> {
        let python = std::env::var("AGENT_SCAN_PYTHON").unwrap_or_else(|_| "python3".to_owned());
        let mut child = Command::new(python)
            .arg("-c")
            .arg(PYTHON_REDACTOR)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Do not allow an exception that might include scanned content to
            // reach a terminal or log before this binary fails closed.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ScanError::RedactorStart)?;
        let stdin = child.stdin.take().ok_or(ScanError::RedactorStart)?;
        let stdout = child.stdout.take().ok_or(ScanError::RedactorStart)?;
        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    fn request(&mut self, request: &serde_json::Value) -> Result<serde_json::Value, ScanError> {
        serde_json::to_writer(&mut self.stdin, request)?;
        self.stdin
            .write_all(b"\n")
            .map_err(|_| ScanError::RedactorFailed)?;
        self.stdin.flush().map_err(|_| ScanError::RedactorFailed)?;

        let mut line = String::new();
        if self
            .stdout
            .read_line(&mut line)
            .map_err(|_| ScanError::RedactorFailed)?
            == 0
        {
            return Err(ScanError::RedactorFailed);
        }
        serde_json::from_str(&line).map_err(|_| ScanError::RedactorProtocol)
    }

    fn redact(&mut self, content: &str) -> Result<String, ScanError> {
        self.request(&json!({ "operation": "redact", "content": content }))?
            .get("content")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or(ScanError::RedactorProtocol)
    }

    fn skill_name(&mut self, content: &str, skill_root: &Path) -> Result<String, ScanError> {
        self.request(&json!({
            "operation": "frontmatter",
            "content": content,
            "path": display_path(skill_root),
        }))?
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(ScanError::RedactorProtocol)
    }

    fn finish(mut self) -> Result<(), ScanError> {
        drop(self.stdin);
        let status = self.child.wait().map_err(|_| ScanError::RedactorFailed)?;
        if status.success() {
            Ok(())
        } else {
            Err(ScanError::RedactorFailed)
        }
    }
}

#[derive(Default)]
struct ContentCache {
    // Per-invocation target identity cache. It intentionally caches only values
    // that have passed the exact Python redactor and is never persisted across
    // scans, so a new scan observes changed files.
    values: HashMap<String, String>,
}

fn absolute_lexical(path: &Path) -> Result<PathBuf, ScanError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|source| ScanError::Read {
                path: path.display().to_string(),
                source,
            })
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn io_error(path: &Path, source: std::io::Error) -> ScanError {
    ScanError::Read {
        path: display_path(path),
        source,
    }
}

fn find_skill_md(directory: &Path) -> Result<Option<PathBuf>, ScanError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| io_error(directory, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(directory, source))?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries
        .into_iter()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("skill.md")
        })
        .map(|entry| entry.path()))
}

fn target_identity(
    _path: &Path,
    metadata: &fs::Metadata,
    allow_binary: bool,
) -> Result<String, ScanError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(format!(
            "{}:{}:{allow_binary}",
            metadata.dev(),
            metadata.ino()
        ))
    }
    #[cfg(not(unix))]
    {
        let canonical = fs::canonicalize(_path).map_err(|source| io_error(_path, source))?;
        Ok(format!("{}:{allow_binary}", canonical.display()))
    }
}

fn file_content(
    path: &Path,
    allow_binary: bool,
    redactor: &mut PythonRedactor,
    cache: &mut ContentCache,
) -> Result<String, ScanError> {
    let metadata = fs::metadata(path).map_err(|source| io_error(path, source))?;
    let identity = target_identity(path, &metadata, allow_binary)?;
    if let Some(value) = cache.values.get(&identity) {
        return Ok(value.clone());
    }

    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    let content = match String::from_utf8(bytes) {
        Ok(text) => redactor.redact(&text)?,
        Err(error) if allow_binary => {
            let hash = Sha256::digest(error.into_bytes());
            format!("{BINARY_FILE_DESCRIPTION_PREFIX}{hash:x}")
        }
        Err(_) => {
            return Err(ScanError::InvalidSkill {
                path: display_path(path),
                reason: "instruction or script file is not valid UTF-8".to_owned(),
            });
        }
    };
    cache.values.insert(identity, content.clone());
    Ok(content)
}

fn relative_path(root: &Path, path: &Path) -> Result<String, ScanError> {
    path.strip_prefix(root)
        .map(|path| {
            path.to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
        })
        .map_err(|_| ScanError::InvalidSkill {
            path: display_path(path),
            reason: "file escaped skill root".to_owned(),
        })
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    ancestors: &mut HashSet<String>,
    redactor: &mut PythonRedactor,
    cache: &mut ContentCache,
    files: &mut Vec<SkillFile>,
) -> Result<(), ScanError> {
    let directory_metadata =
        fs::metadata(directory).map_err(|source| io_error(directory, source))?;
    let identity = target_identity(directory, &directory_metadata, false)?;
    if !ancestors.insert(identity.clone()) {
        return Err(ScanError::InvalidSkill {
            path: display_path(directory),
            reason: "symbolic link cycle".to_owned(),
        });
    }

    let result = (|| {
        let mut entries = fs::read_dir(directory)
            .map_err(|source| io_error(directory, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| io_error(directory, source))?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut child_directories = Vec::new();
        for entry in entries {
            let path = entry.path();
            let metadata = fs::metadata(&path).map_err(|source| io_error(&path, source))?;
            if metadata.is_dir() {
                child_directories.push(path);
            } else if metadata.is_file() {
                let relative = relative_path(root, &path)?;
                let extension = relative
                    .rsplit_once('.')
                    .map_or(relative.as_str(), |(_, ext)| ext)
                    .to_ascii_lowercase();
                let allow_binary = !matches!(extension.as_str(), "md" | "py" | "js" | "ts" | "sh");
                files.push(SkillFile {
                    path: relative,
                    content: file_content(&path, allow_binary, redactor, cache)?,
                });
            } else {
                return Err(ScanError::InvalidSkill {
                    path: display_path(&path),
                    reason: "skill file is not a regular file".to_owned(),
                });
            }
        }
        // Mirror skill_client._walk_skill_regular_files: yield every regular
        // file at this level before descending into child directories, and
        // visit those children in lexical order.
        for child in child_directories {
            collect_regular_files(root, &child, ancestors, redactor, cache, files)?;
        }
        Ok(())
    })();
    ancestors.remove(&identity);
    result
}

fn inspect_skill(
    skill_root: &Path,
    redactor: &mut PythonRedactor,
    cache: &mut ContentCache,
) -> Result<InspectedSkill, ScanError> {
    let skill_md = find_skill_md(skill_root)?.ok_or_else(|| ScanError::InvalidSkill {
        path: display_path(skill_root),
        reason: "SKILL.md was not found".to_owned(),
    })?;
    let frontmatter_content =
        fs::read_to_string(&skill_md).map_err(|source| io_error(&skill_md, source))?;
    // Parse with the same PyYAML-backed implementation as the Python CLI. This
    // avoids accepting a subtly different YAML dialect merely because traversal
    // and serialization happen in Rust.
    let name = redactor.skill_name(&frontmatter_content, skill_root)?;
    let mut files = Vec::new();
    collect_regular_files(
        skill_root,
        skill_root,
        &mut HashSet::new(),
        redactor,
        cache,
        &mut files,
    )?;
    Ok(InspectedSkill {
        name,
        installation_path: display_path(skill_root),
        files,
        error: None,
    })
}

fn child_skill_directories(root: &Path) -> Result<Vec<PathBuf>, ScanError> {
    let children = fs::read_dir(root)
        .map_err(|source| io_error(root, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(root, source))?;
    // Keep the filesystem enumeration order. Python's inspect_skills_dir uses
    // os.listdir() without reordering, and that order is observable in inspect
    // JSON even though files inside each skill are deterministically sorted.
    let mut skills = Vec::new();
    for child in children {
        let path = child.path();
        if fs::metadata(&path)
            .map_err(|source| io_error(&path, source))?
            .is_dir()
            && find_skill_md(&path)?.is_some()
        {
            skills.push(path);
        }
    }
    Ok(skills)
}

fn inspect_path(
    supplied: &Path,
    redactor: &mut PythonRedactor,
    cache: &mut ContentCache,
) -> Result<(String, InspectedPath), ScanError> {
    let supplied = absolute_lexical(supplied)?;
    let metadata = fs::metadata(&supplied).map_err(|source| io_error(&supplied, source))?;
    if metadata.is_file() {
        if !supplied
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("skill.md"))
        {
            return Err(ScanError::UnsupportedSurface);
        }
        let skill_root = supplied.parent().ok_or_else(|| ScanError::InvalidSkill {
            path: display_path(&supplied),
            reason: "SKILL.md has no parent directory".to_owned(),
        })?;
        let client_path = skill_root
            .parent()
            .ok_or_else(|| ScanError::InvalidSkill {
                path: display_path(skill_root),
                reason: "skill directory has no parent directory".to_owned(),
            })?
            .to_path_buf();
        let skill = inspect_skill(skill_root, redactor, cache)?;
        let path = display_path(&client_path);
        return Ok((
            path.clone(),
            InspectedPath {
                client: display_path(&supplied),
                path,
                servers: Vec::new(),
                skills: vec![skill],
                error: None,
            },
        ));
    }
    if !metadata.is_dir() {
        return Err(ScanError::UnsupportedSurface);
    }

    if find_skill_md(&supplied)?.is_some() {
        let client_path = supplied.parent().ok_or_else(|| ScanError::InvalidSkill {
            path: display_path(&supplied),
            reason: "skill directory has no parent directory".to_owned(),
        })?;
        let skill = inspect_skill(&supplied, redactor, cache)?;
        let path = display_path(client_path);
        return Ok((
            path.clone(),
            InspectedPath {
                client: display_path(&supplied),
                path,
                servers: Vec::new(),
                skills: vec![skill],
                error: None,
            },
        ));
    }

    // Python resolves a generic directory before listing its direct skill
    // children. Preserve that behavior for symlinked workspace aliases while
    // retaining the original explicit path for client attribution.
    let canonical_root =
        fs::canonicalize(&supplied).map_err(|source| io_error(&supplied, source))?;
    let skills = child_skill_directories(&canonical_root)?
        .iter()
        .map(|path| inspect_skill(path, redactor, cache))
        .collect::<Result<Vec<_>, _>>()?;
    let path = display_path(&supplied);
    Ok((
        path.clone(),
        InspectedPath {
            client: path.clone(),
            path,
            servers: Vec::new(),
            skills,
            error: None,
        },
    ))
}

fn run(cli: Cli) -> Result<(), ScanError> {
    let Commands::Inspect(args) = cli.command;
    if !args.skills || !args.json {
        return Err(ScanError::UnsupportedSurface);
    }
    let mut redactor = PythonRedactor::start()?;
    let mut cache = ContentCache::default();
    let mut output = serde_json::Map::new();
    for path in args.paths {
        let (key, inspected) = inspect_path(&path, &mut redactor, &mut cache)?;
        output.insert(key, serde_json::to_value(inspected)?);
    }
    // Do not serialize output before the worker has completed successfully;
    // otherwise a worker failure could leave a partial, potentially unsafe result.
    redactor.finish()?;
    serde_json::to_writer_pretty(std::io::stdout(), &output)?;
    println!();
    Ok(())
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("snyk-agent-scan-rust: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn hashes_allowed_binary_content() {
        let directory = TempDir::new().unwrap();
        let asset = directory.path().join("image.bin");
        fs::write(&asset, [0xff, 0x00, 0x01]).unwrap();
        let expected = format!(
            "{BINARY_FILE_DESCRIPTION_PREFIX}{}",
            format!("{:x}", Sha256::digest([0xff, 0x00, 0x01]))
        );
        assert_eq!(
            expected,
            "Binary file. Hash: 942e1e2a66a427b6551732f758bc314f22b9cdec9365a3425c9184de299392b5"
        );
    }

    #[test]
    fn accepts_skill_md_name_case_insensitively() {
        let directory = TempDir::new().unwrap();
        fs::write(
            directory.path().join("skill.md"),
            "---\nname: demo\ndescription: useful\n---\n",
        )
        .unwrap();
        assert!(find_skill_md(directory.path()).unwrap().is_some());
    }
}
