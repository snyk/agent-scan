"""Direct delivery of Agent Guard hook events to Agent Monitor."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import NamedTuple

import aiohttp

from agent_scan.hook_version import HOOK_VERSION
from agent_scan.utils import get_hostname, get_username
from agent_scan.verify_api import RETRYABLE_TRANSPORT_EXCEPTIONS, platform_client_session
from agent_scan.version import version_info


class HookClient(NamedTuple):
    target_folder_field: str
    session_field: str
    endpoint: str


HOOK_CLIENTS = {
    "claude-code": HookClient("cwd", "session_id", "/hidden/agent-monitor/hooks/claude-code"),
    "cursor": HookClient("workspace_roots", "conversation_id", "/hidden/agent-monitor/hooks/cursor"),
    "codex": HookClient("cwd", "session_id", "/hidden/agent-monitor/hooks/codex"),
}
_HOOK_REQUEST_TIMEOUT_SECONDS = 15


async def _post_hook_event(url: str, body: bytes, headers: dict[str, str], max_retries: int) -> tuple[bool, str]:
    """POST once per attempt, retrying only transport errors like the analysis path does."""
    timeout = aiohttp.ClientTimeout(total=_HOOK_REQUEST_TIMEOUT_SECONDS)
    detail = ""
    for attempt in range(max_retries):
        try:
            async with platform_client_session() as session:
                async with session.post(url, data=body, headers=headers, timeout=timeout) as response:
                    if response.status >= 400:
                        # A rejected event will be rejected again; only transport faults retry.
                        return False, f"HTTP {response.status}"
                    return True, ""
        except RETRYABLE_TRANSPORT_EXCEPTIONS as error:
            detail = str(error) or type(error).__name__
            if attempt + 1 < max_retries:
                await asyncio.sleep(2**attempt)
        except Exception as error:
            return False, str(error)
    return False, detail


def send_hook_event(
    base_url: str,
    hook_client: str,
    push_key: str,
    payload: str,
    machine_id: str,
    *,
    max_retries: int = 1,
) -> tuple[bool, str]:
    """POST a hook event using the same wire contract as the hook scripts.

    ``max_retries`` defaults to a single attempt: session-start discovery runs inside
    the agent's hook budget, so waiting out a backoff there would cost more than the
    event is worth. One-shot callers such as ``guard install`` can opt into retries.
    """
    client = HOOK_CLIENTS.get(hook_client)
    if client is None:
        return False, f"unknown client: {hook_client}"
    if not machine_id.strip():
        return False, "machine ID is required"

    hostname = get_hostname()
    x_user = json.dumps(
        {
            "hostname": hostname,
            "username": get_username(),
            "identifier": machine_id,
        },
        separators=(",", ":"),
    )
    encoded_payload = base64.b64encode(payload.encode()).decode()
    body = f"base64:{encoded_payload}".encode()
    script_extension = "ps1" if sys.platform == "win32" else "sh"
    url = f"{base_url.rstrip('/')}{client.endpoint}?version={HOOK_VERSION}"
    headers = {
        "User-Agent": f"snyk/snyk-agent-guard.{script_extension} Agent Scan v{version_info}",
        "X-User": x_user,
        "Content-Type": "text/plain",
        "X-Client-Id": push_key,
    }

    try:
        return asyncio.run(_post_hook_event(url, body, headers, max_retries))
    except Exception as error:
        # Delivery is best-effort; never let it break the caller.
        return False, str(error)
