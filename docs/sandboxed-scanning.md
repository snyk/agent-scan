# Sandboxed scanning

`snyk-agent-scan sandbox-scan` inspects an MCP server inside an ephemeral,
network-restricted Docker sandbox, for servers you don't want to execute
directly on your own machine: registry-resolved `npm:`/`pypi:` direct-scan
targets, or your own unpublished server source.

**Today, this reports tool/prompt/resource discovery only — no vulnerability
findings.** The sandboxed invocation runs `snyk-agent-scan inspect` internally,
not `scan`, deliberately: `scan` needs a Snyk API credential, and putting that
credential inside the same container/namespace as the untrusted scanned server
has its own risks that are being designed properly rather than bolted on here.
Real vulnerability findings for sandboxed scans are a planned follow-on.

## What it covers

- **Registry-resolved targets**: `npm:pkg@version`, `pypi:pkg@version` — the
  same resolution `snyk-agent-scan scan npm:...` already does, run inside the
  sandbox instead of on the host.
- **Your own source**: a directory containing your server's code plus an
  `mcp.json` describing how to launch it (the same `command`/`args`/`cwd`/`env`
  shape any MCP config file uses).

## What it doesn't cover (yet)

- **Vulnerability/security analysis findings** — see the note above. Only
  tool/prompt/resource discovery is reported, the same data
  `snyk-agent-scan inspect` reports for an unsandboxed target.
- `oci:` (Docker-image) targets and client-supplied Dockerfiles — these need
  nested Docker, which is out of scope for this phase.
- Private registries or private images — no credential injection yet.
- Remote, client-hosted MCP servers — those need no sandbox at all; scan them
  directly with `snyk-agent-scan scan --url ...`.

## Usage

```bash
# A registry-resolved package
snyk-agent-scan sandbox-scan npm:some-mcp-server@1.2.3 --build

# Your own server source
snyk-agent-scan sandbox-scan mcp.json --input-dir ./my-server --build
```

`--input-dir` is mounted read-only at `/scan-input` inside the sandbox; `TARGET`
is a path relative to it. `--build` (re)builds the sandbox images first — omit
it on repeat runs once they're built.

Output is JSON, keyed by the literal in-container path
`/scan-config/mcp.generated.json` (not a real path on your machine) — the same
shape `snyk-agent-scan inspect --json` produces for any target. There is no
rich-text mode for `sandbox-scan` yet.

## How isolation works

Two throwaway containers, both removed after the scan regardless of outcome:

- An egress-allowlist proxy (default-deny, only Snyk's API and the npm/pypi
  registries are reachable).
- The sandbox itself, on a Docker network created with `--internal` — it has
  no route to the internet except through the proxy container. A scanned
  server that ignores its proxy configuration and tries a direct connection
  simply has nowhere to go.
