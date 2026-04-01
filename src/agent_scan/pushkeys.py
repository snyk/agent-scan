"""Push key minting and revocation for EVO."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

PLATFORM_API_VERSION = "2025-08-28"


def _build_push_key_url(base_url: str, tenant_id: str) -> str:
    base = base_url.rstrip("/")
    if "/hidden" not in base:
        base += "/hidden"
    return f"{base}/tenants/{tenant_id}/mcp-scan/push-key?version={PLATFORM_API_VERSION}"


def _is_localhost(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1")


def mint_push_key(
    base_url: str,
    tenant_id: str,
    snyk_token: str,
    description: str | None = None,
) -> str:
    """Mint a new push key via the Snyk Platform API.

    Returns the client_id (push key) string.
    Raises RuntimeError on failure.
    """
    url = _build_push_key_url(base_url, tenant_id)

    body = json.dumps({"description": description}).encode() if description else b""

    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if snyk_token and not _is_localhost(base_url):
        req.add_header("Authorization", f"token {snyk_token}")

    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except HTTPError as e:
        body_text = e.read().decode(errors="replace")
        raise RuntimeError(f"Push key minting failed: HTTP {e.code} — {body_text}") from e
    except (TimeoutError, URLError) as e:
        raise RuntimeError(f"Push key minting failed: {e}") from e

    client_id = data.get("client_id")
    if not client_id:
        raise RuntimeError(f"Unexpected push key response: {data}")
    return client_id


def revoke_push_key(
    base_url: str,
    tenant_id: str,
    snyk_token: str,
    client_id: str,
) -> None:
    """Revoke a push key via the Snyk Platform API.

    Raises RuntimeError on failure.
    """
    url = _build_push_key_url(base_url, tenant_id)

    req = Request(url, method="DELETE")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-client-id", client_id)
    if snyk_token and not _is_localhost(base_url):
        req.add_header("Authorization", f"token {snyk_token}")

    try:
        with urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"Push key revocation failed: HTTP {resp.status}")
    except HTTPError as e:
        body_text = e.read().decode(errors="replace")
        raise RuntimeError(f"Push key revocation failed: HTTP {e.code} — {body_text}") from e
    except (TimeoutError, URLError) as e:
        raise RuntimeError(f"Push key revocation failed: {e}") from e
