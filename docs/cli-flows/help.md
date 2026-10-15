# `help`

`snyk-agent-scan help`. Prints the argparse help text and exits. No scanning, no network, no filesystem access beyond the optional config file.

Related spellings: `snyk-agent-scan --help` alone is handled inside `argparse` itself and exits **before** the banner and before any code in `main()` after `parse_args()` runs; `snyk-agent-scan <command> --help` is also argparse-internal.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal
    end
    box rgba(80,140,220,0.18) Flow logic
    participant CLI as cli.main
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / process table
    end

    T->>CLI: snyk-agent-scan help
    CLI->>OS: psutil parent cmdline (program name for the usage line)
    CLI->>CLI: build argparse tree, parse_args (command = help)
    CLI->>CLI: resolve_server_io_default, enforce_consent_requirements (no effect, flags absent)
    CLI->>T: banner "Snyk Agent Scan vX"
    CLI->>CLI: setup_logging (verbose attribute absent, so logging stays off)
    CLI->>T: parser.print_help()
    CLI-->>T: exit code 0
```

## Notes

- `help` is registered as a sub-parser without any arguments, so `--config-file` and the other common flags are not accepted for it.
- The second branch of the dispatch condition, `args.command is None and hasattr(args, "help")`, can never be true because `main()` always injects `scan` when no command is given. It is dead code.
- The banner is printed before the help text for the `help` sub-command only, not for `--help`.
