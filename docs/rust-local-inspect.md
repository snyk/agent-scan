# Experimental Rust local skill inspector

`Cargo.toml` adds an **additive**, experimental binary named
`snyk-agent-scan-rust`. It does not replace the released Python
`snyk-agent-scan` command.

The implementation is deliberately a narrow vertical slice:

```sh
uv sync --extra test --extra dev
cargo build --release
AGENT_SCAN_PYTHON="$PWD/.venv/bin/python" \
  ./target/release/snyk-agent-scan-rust inspect --skills --json /absolute/path/to/skills
```

`AGENT_SCAN_PYTHON` must name an interpreter in which this version of
`agent_scan` is installed. The command exits without producing JSON if the
worker cannot start or fails.

## Supported surface

The binary supports only:

```text
snyk-agent-scan-rust inspect --skills --json PATH [PATH ...]
```

Each explicit `PATH` may be a directory containing `SKILL.md` (case
insensitive), that `SKILL.md` file itself, or a directory whose immediate child
directories are skills. It recursively reads regular files, follows links while
rejecting link cycles, hashes permitted non-UTF-8 assets, and emits the same
inspect JSON shape as the Python implementation for valid skills.

Text content is not redacted by a partial Rust port. The Rust process sends text
only over a private pipe to one Python worker that calls the installed
`agent_scan.redact.redact_text` function. Thus it retains the current
`detect-secrets` plugin configuration, token handling, and redaction markers.
The Rust process caches already-redacted content by target identity for exactly
one invocation, retaining a separate output record for every lexical input.
Nothing is persisted between scans. If the worker fails, the command emits no
partial or unredacted JSON.

This is intentionally not a standalone distribution and is currently validated
on the macOS/Linux Unix identity path. It is an implementation experiment, not
a new supported release artifact.

## Deferred surface

The released Python command remains required for all of the following:

- default machine/client discovery, `--scan-all-users`, configuration files,
  command skills, and all supported agent layouts;
- MCP config parsing, server execution/consent, OAuth, stdio/HTTP/SSE traffic,
  signatures, and error reporting;
- `scan` and its analysis/control-server/push-key API calls, `evo`, and
  `guard` commands;
- Python config-file compatibility, console formatting, CI exit semantics,
  package/standalone-binary release packaging, and Windows support.

The explicit command rejects unsupported modes instead of falling back to a
less secure or differently scoped implementation.

## Equivalence and security regression checks

The Rust unit tests cover case-insensitive `SKILL.md` discovery and binary
hashing. Frontmatter parsing is deliberately delegated to the exact Python
implementation and is covered by the executable equivalence test at
`tests/rust/test_local_inspect_equivalence.py`, which compares the Rust JSON
with the Python CLI over `tests/skills`, checks a real `detect-secrets` AWS key fixture
is redacted by both, and verifies a missing worker yields exit 2 with no stdout.

Run it after a release build:

```sh
AGENT_SCAN_RUST_BINARY="$PWD/target/release/snyk-agent-scan-rust" \
  uv run pytest tests/rust/test_local_inspect_equivalence.py -q --no-cov
```

## Reproducible performance check

All numbers are process-cold (a new process per sample) on a warm filesystem
cache; ordinary users cannot safely flush the global macOS cache. The command
uses no network, an empty synthetic `HOME`, and `tests/skills` (17 directory
skills, 277 files, 3,058,291 bytes). It sends JSON to `/dev/null` so it includes
serialization but not terminal rendering.

```sh
# Python baseline
for n in $(seq 1 12); do
  HOME="$PWD/.bench-home" SNYK_TOKEN= \
    ./.venv/bin/snyk-agent-scan inspect --skills --json "$PWD/tests/skills" >/dev/null
done

# Rust slice; use the same Python redaction engine
for n in $(seq 1 12); do
  HOME="$PWD/.bench-home" SNYK_TOKEN= AGENT_SCAN_PYTHON="$PWD/.venv/bin/python" \
    ./target/release/snyk-agent-scan-rust inspect --skills --json "$PWD/tests/skills" >/dev/null
done
```

The companion benchmark script `rust/bench_local_inspect.py` records raw fresh
process timings, machine metadata, corpus shape, and medians for the Python
baseline and Rust binary. It also measures a repeated-alias corpus, where the
per-invocation identity cache is expected to matter.

### Recorded result

On an Apple M5 Pro (arm64, 48 GiB RAM), macOS 26.6.2, CPython 3.13.14, release
Rust 1.98.0, the script above recorded the following. The filesystem was warm,
there was no network, and each sample was a new process; these are not
cross-machine claims.

| Workload | Python median (n) | Rust median (n) | Result |
| --- | ---: | ---: | --- |
| `--help` process startup | 367.2 ms (30) | 5.1 ms (30) | 98.6% lower for help-only startup |
| Full local fixture corpus | 8.815 s (12) | 9.023 s (12) | Rust slice was 2.4% slower |
| Eight aliases of three skills | 5.694 s (10) | 1.099 s (10) | 80.7% lower with the per-invocation identity cache |

The full-corpus result is the important guardrail: the Rust layer deliberately
retains the exact Python redactor, which remains dominant, so this vertical
slice is not evidence for a full rewrite. The alias result is evidence for the
cache boundary, but the same identity-cache optimization is also implementable
in the existing Python collector. Keep the raw JSON by redirecting the script's
stdout, for example:

```sh
./.venv/bin/python rust/bench_local_inspect.py > rust-local-inspect-results.json
```
