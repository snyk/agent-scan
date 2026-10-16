import pytest
from mcp.shared.auth import OAuthToken

from agent_scan.debug_mcp_auth import run_debug_auth
from agent_scan.oauth_flow import AuthResult
from agent_scan.oauth_store import OAuthTokenStore, StoredServerAuth


@pytest.mark.asyncio
async def test_run_debug_auth_reports_existing_entry(tmp_path, monkeypatch):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put(
        "https://example.com/mcp",
        StoredServerAuth(
            server_name="example",
            client_id="client-1",
            client_secret=None,
            token_url="https://example.com/token",
            mcp_server_url="https://example.com/mcp",
            redirect_uris=["http://127.0.0.1:1234/callback"],
            updated_at=1.0,
            expires_at=2.0,
            token=OAuthToken(access_token="abc", token_type="Bearer", expires_in=3600),
        ),
    )

    async def fake_authenticate_server(url, server_name, store, **kwargs):
        return AuthResult(ok=True, server_url=url, message="ok")

    monkeypatch.setattr("agent_scan.debug_mcp_auth.authenticate_server", fake_authenticate_server)

    result = await run_debug_auth(
        url="https://example.com/mcp",
        server_name="example",
        store=store,
        timeout=1.0,
        verbose=False,
        print_details=False,
    )

    assert result.ok is True
    assert result.server_url == "https://example.com/mcp"


@pytest.mark.asyncio
async def test_run_debug_auth_does_not_print_secrets(tmp_path, monkeypatch, capsys):
    """print_details must never put live credentials on stdout.

    Two things make this test genuinely able to catch a regression rather than
    pass by accident:

    * ``COLUMNS`` is pinned wide before any ``rich.print`` call. ``rich``
      soft-wraps at the console width (80 columns by default when not
      attached to a real terminal), which would fold a long secret across
      multiple lines and let a plain substring check pass even against the
      old leaking ``model_dump()`` code.
    * The secrets are realistic-length OAuth tokens (200+ chars), not short
      12-character fixture strings — a short secret is exactly what would fit
      on one wrapped line and mask the bug the wide-console fix addresses.
    """
    monkeypatch.setenv("COLUMNS", "1000")
    secret_access_token = "SECRETACCESS-" + "a1b2c3d4e5f6g7h8i9j0" * 10  # 213 chars
    secret_refresh_token = "SECRETREFRESH-" + "k1l2m3n4o5p6q7r8s9t0" * 10  # 214 chars
    secret_client_secret = "SECRETCLIENT-" + "u1v2w3x4y5z6a7b8c9d0" * 10  # 213 chars

    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put(
        "https://example.com/mcp",
        StoredServerAuth(
            server_name="example",
            client_id="client-1",
            client_secret=secret_client_secret,
            token_url="https://example.com/token",
            mcp_server_url="https://example.com/mcp",
            redirect_uris=["http://127.0.0.1:1234/callback"],
            updated_at=1.0,
            expires_at=2.0,
            token=OAuthToken(
                access_token=secret_access_token,
                token_type="Bearer",
                expires_in=3600,
                refresh_token=secret_refresh_token,
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
    assert secret_access_token not in out
    assert secret_refresh_token not in out
    assert secret_client_secret not in out
    # The non-secret summary is still printed, so the helper remains useful.
    assert "client-1" in out
