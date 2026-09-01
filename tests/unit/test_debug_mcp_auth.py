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
