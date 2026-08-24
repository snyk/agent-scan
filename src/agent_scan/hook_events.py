"""Direct delivery of Agent Guard hook events to Agent Monitor."""

from __future__ import annotations

import base64
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent_scan.hook_version import HOOK_VERSION
from agent_scan.utils import get_hostname, get_username
from agent_scan.version import version_info

_HOOK_ENDPOINTS = {
    "claude-code": "/hidden/agent-monitor/hooks/claude-code",
    "cursor": "/hidden/agent-monitor/hooks/cursor",
    "codex": "/hidden/agent-monitor/hooks/codex",
}
_HOOK_REQUEST_TIMEOUT_SECONDS = 15


def send_hook_event(
    base_url: str,
    hook_client: str,
    push_key: str,
    payload: str,
    machine_id: str = "",
) -> tuple[bool, str]:
    """POST a hook event using the same wire contract as the hook scripts."""
    endpoint = _HOOK_ENDPOINTS.get(hook_client)
    if endpoint is None:
        return False, f"unknown client: {hook_client}"

    hostname = get_hostname()
    x_user = json.dumps(
        {
            "hostname": hostname,
            "username": get_username(),
            "identifier": machine_id or hostname,
        },
        separators=(",", ":"),
    )
    encoded_payload = base64.b64encode(payload.encode()).decode()
    body = f"base64:{encoded_payload}".encode()
    script_extension = "ps1" if sys.platform == "win32" else "sh"
    url = f"{base_url.rstrip('/')}{endpoint}?version={HOOK_VERSION}"

    request = Request(url, data=body, method="POST")
    request.add_header("User-Agent", f"snyk/snyk-agent-guard.{script_extension} Agent Scan v{version_info}")
    request.add_header("X-User", x_user)
    request.add_header("Content-Type", "text/plain")
    request.add_header("X-Client-Id", push_key)

    try:
        with urlopen(request, timeout=_HOOK_REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", 200)
            if status >= 400:
                return False, f"HTTP {status}"
        return True, ""
    except HTTPError as error:
        return False, f"HTTP {error.code}"
    except (TimeoutError, URLError) as error:
        return False, str(error)
    except Exception as error:
        return False, str(error)
