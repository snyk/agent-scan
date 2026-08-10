# OAuth Credential Handling Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four concrete defects in the OAuth credential handling added by `feat/oauth-resolution`, without changing the storage architecture.

**Architecture:** All four fixes are local to two modules — `src/agent_scan/oauth_store.py` (the file-backed token store and the proactive refresh) and `src/agent_scan/debug_mcp_auth.py` (a diagnostics helper). No new dependencies, no change to the on-disk format, no change to any CLI surface. Each fix is independently testable and independently revertable, and each gets its own commit.

**Tech Stack:** Python 3.10+, `pydantic` v2, `httpx`, `mcp==1.27.0`, `pytest` + `pytest-asyncio`, `ruff` for lint/format.

## Global Constraints

- Branch: `feat/oauth-resolution`. Working tree was clean at plan time; do not rebase or merge `main` as part of this work.
- Python floor is **3.10** (`requires-python = ">=3.10"`). No `match` statements, no 3.11-only stdlib. `ipaddress` and `os.fchmod` are both 3.10-safe.
- **No new dependencies.** `pyproject.toml` pins deliberately and carries CVE overrides; adding a package is out of scope for this plan.
- Run tests via the Makefile: `make test <path>`. Bare `pytest` fails — the suite defines a required `--runner` option, which the Makefile supplies (`--runner=uv`).
- Line length is 120 (`[tool.ruff] line-length = 120`). Double quotes. `ruff` lint selects `E,F,I,B,C4,UP,SIM,TCH,W,RUF`.
- POSIX-mode assertions must be skipped on Windows, matching the existing convention in `tests/unit/test_guard.py`: `@pytest.mark.skipif(sys.platform == "win32", reason=...)`.
- Do **not** add a `CHANGELOG.md` entry. That file is version-keyed and written by the release commit (see `0.5.16` at the tail); adding an unreleased line here would conflict with that flow.
- Every new test must be observed **failing for the intended reason** before its fix is written, except where a step explicitly labels a test as a characterization test.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/agent_scan/oauth_store.py` | Token persistence, permissions, proactive refresh, token-endpoint validation | Modify — Tasks 1, 2, 3, 4 |
| `src/agent_scan/debug_mcp_auth.py` | Diagnostics helper for the interactive auth flow | Modify — Task 2 |
| `tests/unit/test_oauth_store.py` | Unit tests for the store and refresh | Modify — Tasks 1, 2, 3, 4 |
| `tests/unit/test_debug_mcp_auth.py` | Unit tests for the diagnostics helper | Modify — Task 2 |

`oauth_store.py` is ~380 lines and already cohesive (persistence + refresh for one concern). It is not unwieldy and this plan does **not** split it.

Two shared test helpers in `tests/unit/test_oauth_store.py` are extended rather than duplicated:

- `_FakeResponse` gains a `headers` argument (Task 3).
- `_FakeAsyncClient` gains `last_init_kwargs` recording (Task 3).

Task 3 is therefore ordered before Task 4, because Task 4's tests reuse the extended `_FakeResponse`.

---

## Task 1: Create the token file owner-only from the first byte

**Files:**
- Modify: `src/agent_scan/oauth_store.py:160-168` (`OAuthTokenStore._write_raw`)
- Test: `tests/unit/test_oauth_store.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no new public names. `_write_raw(self, data: dict[str, dict]) -> None` keeps its exact signature; callers `put`, `update_token`, `set_token_url` are unchanged.

**Why this is a defect.** The current code writes the token document with builtin `open(tmp, "w")`, which creates the file with `0o666 & ~umask` — `0o644` under the common `umask 022`. The access token, refresh token, and client secret are written into that world-readable file, and only *afterwards* is `os.chmod(tmp, 0o600)` applied. Between the write and the chmod, any local user can read every stored credential. The existing test at `tests/unit/test_oauth_store.py:94` asserts the *final* mode and so passes despite the window.

- [ ] **Step 1: Add the umask-pinning fixture and the two imports it needs**

At the top of `tests/unit/test_oauth_store.py`, the import block is currently:

```python
import json
import stat
import time
```

Replace it with:

```python
import json
import os
import stat
import sys
import time
```

Then add this fixture immediately after the `_entry` helper (after line 36, before the `test_normalize_server_url` parametrize block):

```python
@pytest.fixture
def permissive_umask():
    """Pin a permissive umask for the duration of a test.

    Without this, a developer running with ``umask 077`` would see the
    permission tests pass even against the unfixed code, because the ambient
    umask — not the code — would be what tightened the file.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)
```

- [ ] **Step 2: Write the failing test**

Append to `tests/unit/test_oauth_store.py`:

```python
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not meaningful on Windows")
def test_temp_file_is_owner_only_while_being_written(tmp_path, monkeypatch, permissive_umask):
    """The temp file must be 0600 before any token bytes reach it.

    Regression test: creating it with builtin ``open()`` yields ``0o666 & ~umask``
    (0o644 here) and only tightens it after the write, so the fully-written
    credential file is world-readable for the length of the write.
    """
    path = tmp_path / "store.json"
    tmp_file = tmp_path / "store.json.tmp"
    observed: dict[str, int] = {}

    real_dump = oauth_store.json.dump

    def spy_dump(obj, fp, **kwargs):
        # Sampled at the moment the credentials are being serialized — the exact
        # window the unfixed code leaves open.
        observed["mode"] = stat.S_IMODE(tmp_file.stat().st_mode)
        return real_dump(obj, fp, **kwargs)

    monkeypatch.setattr(oauth_store.json, "dump", spy_dump)
    OAuthTokenStore(path=path).put("https://mcp.linear.app/mcp", _entry())

    assert observed["mode"] == 0o600
```

- [ ] **Step 3: Run the test and confirm it fails for the right reason**

Run: `make test tests/unit/test_oauth_store.py::test_temp_file_is_owner_only_while_being_written ARGS="-v"`

Expected: **FAIL** with `assert 420 == 384`. `420` is `0o644` in decimal and `384` is `0o600`. If you instead see it pass, the fixture is not applied — check that `permissive_umask` is in the test signature.

- [ ] **Step 4: Apply the fix**

In `src/agent_scan/oauth_store.py`, replace `_write_raw` in full:

```python
    def _write_raw(self, data: dict[str, dict]) -> None:
        # Create the directory owner-only from the start; the chmod covers the
        # case where it already existed with looser permissions.
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(self.path.parent, 0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        # Open at 0o600 *before* any token bytes are written. Builtin open()
        # would create the file at 0o666 & ~umask (0o644 under the usual
        # umask 022) and only tighten it afterwards, leaving a fully-written
        # credential file readable by every local user for the length of the
        # write.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            # os.open's mode argument is masked by umask; fchmod is not, so this
            # pins 0o600 regardless of the umask the caller runs with.
            os.fchmod(f.fileno(), 0o600)
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
```

Notes for the implementer:

- `os.fdopen` takes ownership of `fd`, so the `with` block closes it on any exception. Do not add a bare `os.close(fd)` — that would double-close.
- The `f.flush()` / `os.fsync(...)` pair is **durability, not security**: it makes the "atomic write" actually survive a crash rather than leaving a zero-length store. If you want the minimal security-only diff, drop those two lines; nothing else depends on them.
- `mode=0o700` on `mkdir` applies only to the final path component and only when the directory is actually created, which is why the explicit `chmod` stays.

- [ ] **Step 5: Run the test and confirm it passes**

Run: `make test tests/unit/test_oauth_store.py::test_temp_file_is_owner_only_while_being_written ARGS="-v"`

Expected: **PASS**

- [ ] **Step 6: Add the directory characterization test**

This one **passes before and after** the fix — `_write_raw` already chmods the parent to `0o700`. It is worth adding anyway: nothing currently pins that behavior, so a future refactor could drop it silently. Label it as such so no one mistakes it for a regression test.

Append to `tests/unit/test_oauth_store.py`:

```python
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not meaningful on Windows")
def test_store_directory_is_owner_only(tmp_path, permissive_umask):
    """Characterization test: the store directory is 0700, including when created.

    Passes before and after the temp-file fix. It exists so that the directory
    tightening cannot be removed without a test failing.
    """
    store_dir = tmp_path / "nested" / ".mcp-scan"
    OAuthTokenStore(path=store_dir / "store.json").put("https://mcp.linear.app/mcp", _entry())

    assert stat.S_IMODE(store_dir.stat().st_mode) == 0o700
```

- [ ] **Step 7: Run the whole store suite to check nothing regressed**

Run: `make test tests/unit/test_oauth_store.py ARGS="-v"`

Expected: **PASS**, including the pre-existing `test_store_roundtrip_and_permissions`, which asserts the final mode is `0o600`.

- [ ] **Step 8: Commit**

```bash
git add src/agent_scan/oauth_store.py tests/unit/test_oauth_store.py
git commit -m "fix(oauth): create the token store file 0600 before writing credentials

Builtin open() created the temp file at 0o666 & ~umask and only chmod'd it
to 0600 after the tokens were written, leaving a world-readable credential
file for the duration of the write. Open with os.open(..., 0o600) and pin
with fchmod instead."
```

---

## Task 2: Stop the diagnostics helper printing live credentials

**Files:**
- Modify: `src/agent_scan/oauth_store.py` — add `StoredServerAuth.safe_summary`
- Modify: `src/agent_scan/debug_mcp_auth.py:39-40`
- Test: `tests/unit/test_oauth_store.py`, `tests/unit/test_debug_mcp_auth.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `StoredServerAuth.safe_summary(self) -> dict[str, object]` — a non-secret dict describing one store entry. Used by `debug_mcp_auth.run_debug_auth`, and available to any future `--list` / logging code.

**Why this is a defect.** `debug_mcp_auth.py:39-40` prints `json.dumps(entry.model_dump(mode="json"), indent=2)`, which is the *complete* credential set — `access_token`, `refresh_token`, and `client_secret` — to stdout. `main()` at `debug_mcp_auth.py:70` hardcodes `print_details=True`, so running the module dumps every secret for that server to the terminal, where it lands in scrollback, `script`/`tee` logs, and CI output. The module ships inside the wheel (`packages = ["src/agent_scan"]`).

An alternative is deleting the module outright. This plan keeps it and makes it safe, because it has a test and a plausible support use; if you would rather delete it, delete `src/agent_scan/debug_mcp_auth.py` and `tests/unit/test_debug_mcp_auth.py` and skip to Task 3 — but still add `safe_summary`, since Task 2's Step 2 test and any future diagnostics depend on it.

- [ ] **Step 1: Write the failing test for `safe_summary`**

Append to `tests/unit/test_oauth_store.py`:

```python
def test_safe_summary_omits_secrets():
    entry = _entry(token=_token(access="SECRETACCESS", refresh="SECRETREFRESH"))
    entry.client_secret = "SECRETCLIENT"

    summary = entry.safe_summary()
    rendered = json.dumps(summary)

    assert "SECRETACCESS" not in rendered
    assert "SECRETREFRESH" not in rendered
    assert "SECRETCLIENT" not in rendered
    # Presence is still reportable without disclosing the values.
    assert summary["has_refresh_token"] is True
    assert summary["has_client_secret"] is True
    # Non-secret identifiers stay useful for diagnostics.
    assert summary["client_id"] == "client-123"
    assert summary["token_url"] == "https://mcp.linear.app/token"
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `make test tests/unit/test_oauth_store.py::test_safe_summary_omits_secrets ARGS="-v"`

Expected: **FAIL** with `AttributeError: 'StoredServerAuth' object has no attribute 'safe_summary'`

- [ ] **Step 3: Implement `safe_summary`**

In `src/agent_scan/oauth_store.py`, add this method to `StoredServerAuth`, immediately after `is_access_token_expired` (which ends at line 132):

```python
    def safe_summary(self) -> dict[str, object]:
        """Non-secret description of this entry, for diagnostics and logs.

        Deliberately omits ``access_token``, ``refresh_token`` and
        ``client_secret``. Anything that prints or logs an entry must go through
        here — ``model_dump()`` returns the live credentials verbatim.
        """
        return {
            "server_name": self.server_name,
            "mcp_server_url": self.mcp_server_url,
            "client_id": self.client_id,
            "token_url": self.token_url,
            "redirect_uris": self.redirect_uris,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "has_client_secret": self.client_secret is not None,
            "has_refresh_token": self.token.refresh_token is not None,
            "access_token_expired": self.is_access_token_expired(),
        }
```

`client_id` is intentionally included: in OAuth it is a public identifier, not a secret, and it is the field you actually need when debugging a DCR problem.

- [ ] **Step 4: Run it and confirm it passes**

Run: `make test tests/unit/test_oauth_store.py::test_safe_summary_omits_secrets ARGS="-v"`

Expected: **PASS**

- [ ] **Step 5: Write the failing test for the helper's output**

Append to `tests/unit/test_debug_mcp_auth.py`:

```python
@pytest.mark.asyncio
async def test_run_debug_auth_does_not_print_secrets(tmp_path, monkeypatch, capsys):
    """print_details must never put live credentials on stdout."""
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put(
        "https://example.com/mcp",
        StoredServerAuth(
            server_name="example",
            client_id="client-1",
            client_secret="SECRETCLIENT",
            token_url="https://example.com/token",
            mcp_server_url="https://example.com/mcp",
            redirect_uris=["http://127.0.0.1:1234/callback"],
            updated_at=1.0,
            expires_at=2.0,
            token=OAuthToken(
                access_token="SECRETACCESS",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="SECRETREFRESH",
            ),
        ),
    )

    async def fake_authenticate_server(url, server_name, store, **kwargs):
        return AuthResult(ok=True, server_url=url, message="ok")

    monkeypatch.setattr("agent_scan.debug_mcp_auth.authenticate_server", fake_authenticate_server)

    await run_debug_auth(
        url="https://example.com/mcp",
        server_name="example",
        store=store,
        timeout=1.0,
        verbose=True,
        print_details=True,
    )

    out = capsys.readouterr().out
    assert "SECRETACCESS" not in out
    assert "SECRETREFRESH" not in out
    assert "SECRETCLIENT" not in out
    # The non-secret summary is still printed, so the helper remains useful.
    assert "client-1" in out
```

The secret values are deliberately single unbroken words. `rich` soft-wraps at the console width, and a hyphenated or spaced value could be split across lines and defeat a plain substring assertion.

- [ ] **Step 6: Run it and confirm it fails**

Run: `make test tests/unit/test_debug_mcp_auth.py::test_run_debug_auth_does_not_print_secrets ARGS="-v"`

Expected: **FAIL** on `assert "SECRETACCESS" not in out` — the current code dumps the full model.

- [ ] **Step 7: Apply the fix**

In `src/agent_scan/debug_mcp_auth.py`, the current block is:

```python
    if entry is not None:
        if print_details:
            rich.print(json.dumps(entry.model_dump(mode="json"), indent=2))
```

Replace it with:

```python
    if entry is not None:
        if print_details:
            # safe_summary(), never model_dump(): the latter includes the access
            # token, refresh token and client secret, which must not reach stdout.
            rich.print(json.dumps(entry.safe_summary(), indent=2))
```

- [ ] **Step 8: Run both test files and confirm they pass**

Run: `make test tests/unit/test_debug_mcp_auth.py tests/unit/test_oauth_store.py ARGS="-v"`

Expected: **PASS**, including the pre-existing `test_run_debug_auth_reports_existing_entry`.

- [ ] **Step 9: Commit**

```bash
git add src/agent_scan/oauth_store.py src/agent_scan/debug_mcp_auth.py \
        tests/unit/test_oauth_store.py tests/unit/test_debug_mcp_auth.py
git commit -m "fix(oauth): stop the debug helper printing access and refresh tokens

run_debug_auth printed entry.model_dump(), i.e. the access token, refresh
token and client secret, to stdout — and main() hardcodes print_details=True.
Add StoredServerAuth.safe_summary() and print that instead."
```

---

## Task 3: Do not follow redirects on the token endpoint

**Files:**
- Modify: `src/agent_scan/oauth_store.py:365-370` (inside `ensure_fresh_token`)
- Test: `tests/unit/test_oauth_store.py`

**Interfaces:**
- Consumes: nothing from Tasks 1–2.
- Produces: no new public names. `ensure_fresh_token(store, server_url, *, timeout=30.0) -> None` keeps its signature and its never-raises contract.
- Extends two test helpers that Task 4 reuses: `_FakeResponse.__init__(self, status_code, content, headers=None)` and `_FakeAsyncClient.last_init_kwargs`.

**Why this is a defect.** The refresh POST at `oauth_store.py:366` uses `httpx.AsyncClient(timeout=timeout, follow_redirects=True)` and sends `refresh_token` plus `client_secret` in the body. `httpx` preserves the method and re-sends the body on `307` and `308`. The target, `entry.token_url`, comes from OAuth discovery metadata captured in `oauth_flow.authenticate_server` — i.e. it is chosen by the remote server. A server that returns `307 Location: https://attacker.example/` therefore receives the long-lived refresh token and the client secret. This is the one item of the four I would call a genuine vulnerability rather than hardening.

Turning redirects off makes the existing `if resp.status_code != 200` branch handle it, so the fix needs no restructuring — only an explicit branch so the log says something useful.

- [ ] **Step 1: Extend the two shared test helpers**

In `tests/unit/test_oauth_store.py`, replace the `_FakeResponse` class:

```python
class _FakeResponse:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content
```

with:

```python
class _FakeResponse:
    def __init__(self, status_code, content, headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
```

Then replace `_FakeAsyncClient.__init__`:

```python
    def __init__(self, *args, **kwargs):
        pass
```

with:

```python
    def __init__(self, *args, **kwargs):
        # Recorded on the base class so subclass instances report here too.
        _FakeAsyncClient.last_init_kwargs = kwargs
```

and add the class attribute alongside the existing `last_post = None`:

```python
    last_post = None
    last_init_kwargs: dict | None = None
```

- [ ] **Step 2: Write the two failing tests**

Append to `tests/unit/test_oauth_store.py`:

```python
@pytest.mark.asyncio
async def test_refresh_disables_redirect_following(tmp_path, monkeypatch):
    """The token exchange must not follow redirects.

    token_url comes from server-controlled discovery metadata, and httpx
    re-sends the body on 307/308 — so following a redirect would hand the
    refresh token and client secret to a host the server chose.
    """
    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _FakeAsyncClient)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(expires_at=time.time() - 10))

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    assert _FakeAsyncClient.last_init_kwargs["follow_redirects"] is False


@pytest.mark.asyncio
async def test_refresh_ignores_a_redirect_response(tmp_path, monkeypatch):
    class _Redirecting(_FakeAsyncClient):
        async def post(self, url, data=None, headers=None):
            _FakeAsyncClient.last_post = {"url": url, "data": data}
            return _FakeResponse(307, b"", {"location": "https://attacker.example/token"})

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _Redirecting)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(token=_token(access="stale"), expires_at=time.time() - 10))

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    # The stale token is left for the connection to try, and the only request
    # made went to the configured endpoint.
    assert store.get("https://mcp.linear.app/mcp").token.access_token == "stale"
    assert _FakeAsyncClient.last_post["url"] == "https://mcp.linear.app/token"
```

- [ ] **Step 3: Run them and confirm the first fails**

Run: `make test tests/unit/test_oauth_store.py ARGS="-v -k redirect"`

Expected: `test_refresh_disables_redirect_following` **FAILS** with `assert True is False`. `test_refresh_ignores_a_redirect_response` already passes — the fake client does not itself follow redirects, so it only pins the fail-closed handling of a `3xx` body. Both are worth keeping.

- [ ] **Step 4: Apply the fix**

In `src/agent_scan/oauth_store.py`, inside `ensure_fresh_token`, the current block is:

```python
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.post(entry.token_url, data=data, headers=headers)
            if resp.status_code != 200:
                logger.info("Refresh for %s failed with status %s; leaving stored token", server_url, resp.status_code)
                return
            new_token = OAuthToken.model_validate_json(resp.content)
```

Replace it with:

```python
        try:
            # follow_redirects=False is deliberate and security-relevant: httpx
            # preserves the method and re-sends the body on 307/308, and
            # entry.token_url comes from server-controlled discovery metadata.
            # Following a redirect would deliver the refresh token and client
            # secret to a host the remote server picked.
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                resp = await client.post(entry.token_url, data=data, headers=headers)
            if resp.status_code in (301, 302, 303, 307, 308):
                logger.warning(
                    "Token endpoint for %s returned a %s redirect to %s; not resending the refresh token",
                    server_url,
                    resp.status_code,
                    resp.headers.get("location", "<no location header>"),
                )
                return
            if resp.status_code != 200:
                logger.info("Refresh for %s failed with status %s; leaving stored token", server_url, resp.status_code)
                return
            new_token = OAuthToken.model_validate_json(resp.content)
```

- [ ] **Step 5: Run the full store suite**

Run: `make test tests/unit/test_oauth_store.py ARGS="-v"`

Expected: **PASS**. In particular `test_ensure_fresh_token_refreshes_expired` must still pass — the helper change to `_FakeAsyncClient.__init__` must not have broken it.

- [ ] **Step 6: Commit**

```bash
git add src/agent_scan/oauth_store.py tests/unit/test_oauth_store.py
git commit -m "fix(oauth): do not follow redirects when exchanging a refresh token

The refresh POST ran with follow_redirects=True against a token_url taken
from server-controlled discovery metadata. httpx re-sends the body on
307/308, so a redirect would have delivered the refresh token and client
secret to a host chosen by the remote server. Fail closed on any 3xx."
```

---

## Task 4: Require HTTPS (or loopback) for the token endpoint

**Files:**
- Modify: `src/agent_scan/oauth_store.py` — add `ipaddress` import, `_is_loopback_host`, `is_secure_token_url`; guard `set_token_url` and `ensure_fresh_token`
- Test: `tests/unit/test_oauth_store.py`

**Interfaces:**
- Consumes: `_FakeResponse(status_code, content, headers=None)` and `_FakeAsyncClient` from Task 3.
- Produces:
  - `is_secure_token_url(url: str) -> bool` — module-level, public. `True` for `https`, or for `http` on a loopback host.
  - `_is_loopback_host(host: str) -> bool` — module-level, private.
  - `OAuthTokenStore.set_token_url` keeps its `(self, server_url: str, token_url: str) -> None` signature and stays non-raising; it now silently declines to persist an insecure endpoint, with a warning log.

**Why this is a defect.** `entry.token_url` is written from discovery metadata (`oauth_flow.py:282-285`) with no scheme check, and `ensure_fresh_token` POSTs the refresh token and client secret to it. A discovery document advertising `http://…` gets the credential sent in cleartext. RFC 6749 §3.2 requires TLS on the token endpoint.

Enforce at both chokepoints rather than with a pydantic field validator. A strict validator on `StoredServerAuth.token_url` would break `oauth_flow._AuthFlowTokenStorage.set_tokens`, which deliberately constructs the entry with `token_url=""` and lets `authenticate_server` fill it in afterwards (`oauth_flow.py:179`).

Plain `http` on loopback is allowed: local MCP servers legitimately use it, and the credential never touches a network. `urlparse("")` yields an empty scheme, so `token_url=""` is rejected by the same check — which is the correct fail-closed result.

- [ ] **Step 1: Write the failing tests**

First, add `is_secure_token_url` to the existing import block in `tests/unit/test_oauth_store.py`:

```python
from agent_scan.oauth_store import (
    OAuthTokenStore,
    PersistentTokenStorage,
    StoredServerAuth,
    ensure_fresh_token,
    is_secure_token_url,
    normalize_server_url,
)
```

Then append:

```python
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://mcp.linear.app/token", True),
        ("https://auth.atlassian.com/oauth/token", True),
        # Loopback http never leaves the host, and local servers use it.
        ("http://127.0.0.1:8080/token", True),
        ("http://localhost:8080/token", True),
        ("http://[::1]:8080/token", True),
        # Anything else must be TLS (RFC 6749 s3.2).
        ("http://mcp.linear.app/token", False),
        ("http://attacker.example/token", False),
        # Empty (an entry whose endpoint was never finalized) and malformed.
        ("", False),
        ("not a url", False),
    ],
)
def test_is_secure_token_url(url, expected):
    assert is_secure_token_url(url) is expected


@pytest.mark.asyncio
async def test_refresh_refuses_a_plaintext_token_endpoint(tmp_path, monkeypatch):
    called = {"post": False}

    class _NoPost(_FakeAsyncClient):
        async def post(self, *a, **k):
            called["post"] = True
            return _FakeResponse(200, b"{}")

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _NoPost)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    entry = _entry(expires_at=time.time() - 10)
    entry.token_url = "http://mcp.linear.app/token"
    store.put("https://mcp.linear.app/mcp", entry)

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    assert called["post"] is False  # the refresh token was never sent in cleartext


def test_set_token_url_rejects_plaintext(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())

    store.set_token_url("https://mcp.linear.app/mcp", "http://attacker.example/token")

    # The original endpoint is retained; the insecure one is never persisted.
    assert store.get("https://mcp.linear.app/mcp").token_url == "https://mcp.linear.app/token"


def test_set_token_url_accepts_https(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())

    store.set_token_url("https://mcp.linear.app/mcp", "https://auth.atlassian.com/oauth/token")

    assert store.get("https://mcp.linear.app/mcp").token_url == "https://auth.atlassian.com/oauth/token"
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `make test tests/unit/test_oauth_store.py ARGS="-v -k 'secure_token_url or plaintext or set_token_url'"`

Expected: collection fails first with `ImportError: cannot import name 'is_secure_token_url'`. That counts as the failing state — it proves the tests are wired to the not-yet-written function. After Step 3 the remaining genuine failure to watch for is `test_refresh_refuses_a_plaintext_token_endpoint`.

- [ ] **Step 3: Add the validation helpers**

In `src/agent_scan/oauth_store.py`, add `ipaddress` to the stdlib import block (it sorts between `contextlib` and `json`, per `ruff`'s isort rules):

```python
import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import time
```

Then add both helpers immediately after the `_PLACEHOLDER_REDIRECT_URI` constant (line 55) and before `normalize_server_url`:

```python
def _is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and any address in 127.0.0.0/8 or ::1."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_secure_token_url(url: str) -> bool:
    """True if a refresh token and client secret may be sent to ``url``.

    RFC 6749 s3.2 requires TLS on the token endpoint. The endpoint we persist is
    taken from server-controlled OAuth discovery metadata, so it is validated
    before use rather than trusted. Plain ``http`` is accepted only for loopback
    hosts: local MCP servers legitimately use it, and the credential never
    reaches a network. An empty or unparseable URL is rejected, which is also
    what makes an entry whose endpoint was never finalized fail closed.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and _is_loopback_host((parsed.hostname or "").lower())
```

- [ ] **Step 4: Guard `set_token_url`**

In `OAuthTokenStore.set_token_url`, insert the check as the first statement in the body, before `key = normalize_server_url(server_url)`:

```python
        if not is_secure_token_url(token_url):
            logger.warning(
                "Refusing to store a non-HTTPS token endpoint for %s: %r", server_url, token_url
            )
            return
```

Also extend that method's docstring with a final paragraph:

```
        Declines to store an endpoint that is neither HTTPS nor loopback, so a
        discovery document cannot arrange for the refresh token to be sent in
        cleartext later. The entry keeps whatever endpoint it already had.
```

- [ ] **Step 5: Guard `ensure_fresh_token`**

In `ensure_fresh_token`, the current block is:

```python
        if entry.token.refresh_token is None:
            # Nothing to refresh with; let the connection fail to auth_failed.
            logger.debug("Stored token for %s expired and has no refresh token", server_url)
            return
```

Add immediately after it, before `data = {...}`:

```python
        if not is_secure_token_url(entry.token_url):
            # Fail closed rather than send the credential in cleartext. The scan
            # then tries the stale token and falls to auth_failed, prompting the
            # user to re-run mcp-auth.
            logger.warning(
                "Refusing to refresh %s: stored token endpoint %r is neither HTTPS nor loopback",
                server_url,
                entry.token_url,
            )
            return
```

- [ ] **Step 6: Run the store suite and confirm everything passes**

Run: `make test tests/unit/test_oauth_store.py ARGS="-v"`

Expected: **PASS**. All the pre-existing tests use `https://mcp.linear.app/token`, so none of them trip the new guard.

- [ ] **Step 7: Commit**

```bash
git add src/agent_scan/oauth_store.py tests/unit/test_oauth_store.py
git commit -m "fix(oauth): require HTTPS or loopback for the token endpoint

token_url is taken from server-controlled discovery metadata and was used
without a scheme check, so a discovery document advertising http:// would
get the refresh token and client secret sent in cleartext. Validate at both
chokepoints: refuse to persist an insecure endpoint, and refuse to refresh
against one."
```

---

## Task 5: Verification sweep

**Files:** none modified — this task only runs checks.

**Interfaces:**
- Consumes: all four fixes from Tasks 1–4.
- Produces: nothing.

- [ ] **Step 1: Run the full unit suite**

Run: `make test tests/unit ARGS="-q"`

Expected: **PASS**, no new failures relative to the branch's pre-change state. If anything unrelated was already failing on `feat/oauth-resolution`, confirm that by stashing and re-running rather than assuming this plan caused it.

- [ ] **Step 2: Lint and format**

```bash
uv run ruff check src/agent_scan/oauth_store.py src/agent_scan/debug_mcp_auth.py \
    tests/unit/test_oauth_store.py tests/unit/test_debug_mcp_auth.py
uv run ruff format --check src/agent_scan/oauth_store.py src/agent_scan/debug_mcp_auth.py \
    tests/unit/test_oauth_store.py tests/unit/test_debug_mcp_auth.py
```

Expected: both clean. If `ruff format --check` reports a diff, run without `--check` and fold the result into the relevant commit with `git commit --amend`.

- [ ] **Step 3: Confirm no secret-printing paths remain**

```bash
grep -rn "model_dump" src/agent_scan/oauth_store.py src/agent_scan/debug_mcp_auth.py
```

Expected: only the `model_dump_json()` calls inside `OAuthTokenStore.put`, `update_token`, and `set_token_url` — those write to the `0600` store file, which is correct. No `model_dump` should feed `rich.print`, `print`, or a `logger` call.

- [ ] **Step 4: Manually confirm the permission fix against a real store**

```bash
uv run -m src.agent_scan.run mcp-auth --help
ls -la ~/.mcp-scan/
```

Expected: `~/.mcp-scan` is `drwx------`, and `oauth-tokens.json` (if present from earlier use) is `-rw-------`. This is a sanity check on the real path, not a substitute for Step 1.

- [ ] **Step 5: Review the four commits as a set**

```bash
git log --oneline origin/main..HEAD | head -10
git diff origin/main...HEAD -- src/agent_scan/oauth_store.py src/agent_scan/debug_mcp_auth.py
```

Confirm each commit is independently revertable and that no unrelated change slipped in.

---

## Deferred, deliberately not in this plan

- **Purge / TTL / `mcp-auth --forget`** — agreed as the likely next step. Needs its own plan: it adds CLI surface, and a TTL changes `StoredServerAuth` semantics.
- **OS keystore backend** (macOS Keychain, Windows DPAPI, Secret Service) — roadmap item, not remediation.
- **Correcting the MDM premise in the docstrings** at `oauth_store.py:3-5`, `oauth_store.py:52-54`, and `oauth_store.py:78-80`. The deployment model is a security admin's own machine, not unattended MDM, and the comments state otherwise — including a claim that `~/.mcp-scan` is "the same working directory the MDM deployment already runs the scan from", which conflates the home directory with the cwd. Worth a small separate commit so it is not buried in a security fix.
- **`--mcp-oauth-tokens-path` now persists to `~/.mcp-scan/oauth-tokens.json`** (`mcp_client.py:73-75`), which it did not on `main`. Not a defect, but undocumented at `docs/cli-reference.md:117`.
- **`CHANGELOG.md`** — one line describing these fixes belongs in the release commit that bumps the version, not here.

## Self-review notes

- Spec coverage: bug 1 → Task 1; bug 2 → Task 2; bug 3 → Task 3; bug 4 → Task 4. All four covered, each with a test that fails first.
- Task order matters in exactly one place: Task 3 extends `_FakeResponse` with `headers`, which Task 4's tests do not use — but Task 4 does reuse `_FakeAsyncClient`, so keep 3 before 4.
- Two tests are labelled as characterization tests (`test_store_directory_is_owner_only`, and `test_refresh_ignores_a_redirect_response`, which passes pre-fix) rather than presented as regression tests. That is intentional and called out at each step.
