
<b>Pattern 1: When validating CLI input or required environment variables, raise a dedicated, user-facing exception that is caught at the top-level to print a clean error message and exit without a full traceback.
</b>

Example code before:
```
def parse_args(argv):
    if "--token" in argv and os.getenv("SNYK_TOKEN") is None:
        raise ValueError("SNYK_TOKEN environment variable not set")
```

Example code after:
```
class ValidationError(Exception):
    """User-facing CLI validation error (no traceback)."""

def parse_args(argv):
    if "--token" in argv and os.getenv("SNYK_TOKEN") is None:
        raise ValidationError("To use Agent Scan, set the SNYK_TOKEN environment variable.")

def main():
    try:
        args = parse_args(sys.argv)
        run(args)
    except ValidationError as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2)
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/snyk/agent-scan/pull/214#discussion_r2926186215
- https://github.com/snyk/agent-scan/pull/199#discussion_r2878421031
</details>


___

<b>Pattern 2: Add targeted unit tests whenever introducing or changing parsing/validation logic, especially for edge cases like unknown flags, missing values, or special-case classification rules.
</b>

Example code before:
```
def parse_block(block):
    # new parsing logic added, but no tests covering unknown flags/missing values
    ...
```

Example code after:
```
def test_parse_block_unknown_flag_does_not_hang():
    argv = ["--control-server", "https://x", "--verbose", "--control-identifier", "id"]
    assert parse_control_servers(argv)[0].identifier == "id"

def test_parse_block_missing_value_is_handled():
    argv = ["--control-server", "https://x", "--control-identifier", "--next-flag"]
    with pytest.raises(ValidationError):
        parse_control_servers(argv)
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/snyk/agent-scan/pull/214#discussion_r2926285319
- https://github.com/snyk/agent-scan/pull/210#discussion_r2926142652
- https://github.com/snyk/agent-scan/pull/149#discussion_r2627380691
</details>


___

<b>Pattern 3: When the same logic appears in multiple places (e.g., defaulting/expanding scan paths, expanding ~ paths, or repeated file existence checks), extract it into a shared helper to prevent drift and simplify future changes.
</b>

Example code before:
```
if not args.files:
    args.files = WELL_KNOWN_PATHS
if args.scan_all_users:
    args.files = expand_paths_all_home_directories(args.files)

# ...later, repeated again in another command path...
if not args.files:
    args.files = WELL_KNOWN_PATHS
if args.scan_all_users:
    args.files = expand_paths_all_home_directories(args.files)
```

Example code after:
```
def normalize_scan_paths(files, scan_all_users: bool) -> list[str]:
    files = files or WELL_KNOWN_PATHS
    return expand_paths_all_home_directories(files) if scan_all_users else files

args.files = normalize_scan_paths(getattr(args, "files", None), getattr(args, "scan_all_users", False))
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/snyk/agent-scan/pull/203#discussion_r2896086754
- https://github.com/snyk/agent-scan/pull/203#discussion_r2896099448
- https://github.com/snyk/agent-scan/pull/141#discussion_r2580395659
</details>


___

<b>Pattern 4: Whenever CLI behavior depends on non-obvious grouping/ordering rules or changes user-facing semantics, document it in either argparse --help text and/or an explicit code comment, and keep README/docs examples in sync with the behavior.
</b>

Example code before:
```
def parse_control_servers(argv):
    """Parse control server arguments from sys.argv."""
    # grouping/ordering expectations are implicit and undocumented
    ...
```

Example code after:
```
def parse_control_servers(argv):
    """
    Parse repeated control-server blocks.

    Expected structure (repeatable):
      --control-server URL [--control-server-H HEADER ...] --control-identifier IDENTIFIER
    """
    ...
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/snyk/agent-scan/pull/214#discussion_r2926207197
- https://github.com/snyk/agent-scan/pull/207#discussion_r2905560074
- https://github.com/snyk/agent-scan/pull/106#discussion_r2409593073
</details>


___

<b>Pattern 5: Prefer cross-platform filesystem handling (pathlib, expanduser, Windows-safe temp files) and avoid assumptions about Unix-only paths; add Windows-specific handling when working with "~", temporary files, or path existence checks.
</b>

Example code before:
```
def inspect_dir(path: str):
    # may fail on Windows due to "~" or path semantics
    entries = os.listdir(path)
    return [os.path.join(path, e) for e in entries]
```

Example code after:
```
from pathlib import Path

def inspect_dir(path: str):
    p = Path(path).expanduser()
    return [str(child) for child in p.iterdir()]

# For temporary files used across OSes:
with tempfile.NamedTemporaryFile(delete=False) as tmp:
    tmp.write(data)
    tmp_path = tmp.name
```

<details><summary>Examples for relevant past discussions:</summary>

- https://github.com/snyk/agent-scan/pull/167#discussion_r2765466883
- https://github.com/snyk/agent-scan/pull/106#discussion_r2409610302
- https://github.com/snyk/agent-scan/pull/203#discussion_r2896099448
</details>


___
