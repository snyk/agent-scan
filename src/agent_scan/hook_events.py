"""Direct delivery of Agent Guard hook events to Agent Monitor."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
from typing import NamedTuple

import aiohttp

from agent_scan.hook_version import HOOK_VERSION
from agent_scan.utils import get_hostname, get_username
from agent_scan.verify_api import RETRYABLE_TRANSPORT_EXCEPTIONS, backend_client_session
from agent_scan.version import version_info


class HookClient(NamedTuple):
    target_folder_field: str
    session_field: str
    endpoint: str


HOOK_CLIENTS = {
    "claude-code": HookClient("cwd", "session_id", "/hidden/agent-monitor/hooks/claude-code"),
    "cursor": HookClient("workspace_roots", "conversation_id", "/hidden/agent-monitor/hooks/cursor"),
    "codex": HookClient("cwd", "session_id", "/hidden/agent-monitor/hooks/codex"),
    "github-copilot": HookClient("cwd", "session_id", "/hidden/agent-monitor/hooks/github-copilot"),
}
_HOOK_REQUEST_TIMEOUT_SECONDS = 15


class RetryPolicy(NamedTuple):
    """Bounded retry with exponential backoff for events sent at install time.

    ``initial_delay`` is the first sleep, each later sleep is multiplied by ``backoff``,
    and ``time_limit`` caps the whole loop (attempts and sleeps together).
    """

    initial_delay: float
    backoff: float
    time_limit: float


# agent-monitor may take ~50 s to answer a hook (it holds a request up to 25 s for the
# session's discovery, then evaluates within its 25 s policy budget), and the forwarder
# scripts cap a request at 60 s. The overall limit matches that endpoint timeout so one
# slow-but-healthy answer is never cut short and an outage is not retried indefinitely.
INSTALL_RETRY_POLICY = RetryPolicy(initial_delay=1.0, backoff=2.0, time_limit=60.0)

_CURL_EXIT_ERRORS = {
    5: ("dns_failure", True),
    6: ("dns_failure", True),
    7: ("connection_refused", True),
    28: ("timeout", True),
    52: ("connection_reset", True),
    55: ("connection_reset", True),
    56: ("connection_reset", True),
}


class FailureKind(NamedTuple):
    """Short machine-readable error label (e.g. ``dns_failure``) and whether a retry may help."""

    label: str
    retryable: bool


def classify_http_status(status: int) -> FailureKind:
    """HTTP 5xx is a service fault worth retrying; anything else rejected is persistent."""
    return FailureKind(f"http_error_{status}", status >= 500)


def classify_failure_detail(detail: str) -> FailureKind:
    """Classify a forwarder-script diagnostic (curl / PowerShell fail-open reason).

    Unknown failures are treated as persistent: retrying a client-side bug only delays the abort.
    """
    text = detail.lower()
    if match := re.search(r"\bhttp (\d{3})\b", text):
        return classify_http_status(int(match.group(1)))
    if "timed out" in text or text.strip() == "timeout":
        return FailureKind("timeout", True)
    if match := re.search(r"curl exit (\d+)|curl: \((\d+)\)", text):
        code = int(match.group(1) or match.group(2))
        if code in _CURL_EXIT_ERRORS:
            return FailureKind(*_CURL_EXIT_ERRORS[code])
        return FailureKind(f"curl_error_{code}", False)
    if re.search(
        r"name or service not known|could not resolve|could not be resolved|no such host|nodename nor servname", text
    ):
        return FailureKind("dns_failure", True)
    if "connection reset" in text or "connection was closed" in text or "forcibly closed" in text:
        return FailureKind("connection_reset", True)
    if "connection refused" in text or "unable to connect" in text:
        return FailureKind("connection_refused", True)
    return FailureKind("rejected", False)


def next_retry_delay(policy: RetryPolicy, attempt: int, started: float, now: float | None = None) -> float | None:
    """Sleep before the next attempt, or None when the overall time limit is spent.

    The limit covers everything since ``started``: earlier attempts and sleeps, not only the
    next sleep. The caller must also cap each attempt at the time that remains, so no attempt
    outlives the limit.

    ``attempt`` is the number of attempts made so far (>= 1).
    """
    delay = policy.initial_delay * policy.backoff ** (attempt - 1)
    elapsed = (time.monotonic() if now is None else now) - started
    if elapsed >= policy.time_limit:
        return None
    # Never sleep past the deadline; an attempt after a clipped sleep would have no time left.
    if elapsed + delay >= policy.time_limit:
        return None
    return delay


# Header naming the agent that fired the hook.
AGENT_SURFACE_HEADER = "X-Agent-Surface"


def agent_surface(hook_client: str) -> str | None:
    """Identify the agent surface from the environment, or None if it isn't Copilot.

    Reported only for the Copilot client. These variables describe the environment, not
    the caller, and they are inherited: another agent running inside a Copilot session
    sees them too, while the hook that fired belongs to whichever config invoked us.

    Copilot's hosts each set AI_AGENT (github_copilot_vscode_agent inside VS Code,
    github_copilot_app_agent for the desktop app) and all of them set COPILOT_CLI. The
    desktop app and the CLI share a surface, since neither users nor enforcement
    distinguish them; a future github_copilot_* host falls in with them rather than
    going unrecognized.
    """
    if hook_client != "github-copilot":
        return None
    ai_agent = os.environ.get("AI_AGENT", "")
    if ai_agent == "github_copilot_vscode_agent":
        return "copilot-vscode"
    if ai_agent.startswith("github_copilot_") or os.environ.get("COPILOT_CLI"):
        return "copilot"
    return None


async def _post_hook_event(
    url: str, body: bytes, headers: dict[str, str], max_retries: int, policy: RetryPolicy | None = None
) -> tuple[bool, str]:
    """POST once per attempt, retrying transport errors and HTTP 5xx.

    Without ``policy`` the loop makes up to ``max_retries`` attempts with a 1 s, 2 s, ... sleep.
    With ``policy`` it retries until the policy's time limit instead. HTTP 4xx is never retried.
    """
    request_timeout = _HOOK_REQUEST_TIMEOUT_SECONDS
    if policy is None:
        policy = RetryPolicy(1.0, 2.0, float("inf"))
    else:
        max_retries = 2**31
        # Time-bounded installs let a slow healthy response use the whole remaining budget.
        request_timeout = float("inf")
    started = time.monotonic()
    detail = ""
    attempt = 0
    while attempt < max_retries:
        attempt += 1
        remaining = policy.time_limit - (time.monotonic() - started)
        timeout = aiohttp.ClientTimeout(total=min(request_timeout, remaining))
        try:
            async with backend_client_session() as session:
                async with session.post(url, data=body, headers=headers, timeout=timeout) as response:
                    if response.status < 400:
                        return True, ""
                    kind = classify_http_status(response.status)
                    detail = f"HTTP {response.status}"
                    if not kind.retryable:
                        # A rejected event will be rejected again; only transport faults and 5xx retry.
                        return False, detail
        except RETRYABLE_TRANSPORT_EXCEPTIONS as error:
            detail = str(error) or type(error).__name__
        except Exception as error:
            return False, str(error)
        delay = next_retry_delay(policy, attempt, started)
        if attempt >= max_retries or delay is None:
            break
        await asyncio.sleep(delay)
    return False, detail


def send_hook_event(
    base_url: str,
    hook_client: str,
    push_key: str,
    payload: str,
    machine_id: str,
    *,
    max_retries: int = 1,
    retry_policy: RetryPolicy | None = None,
) -> tuple[bool, str]:
    """POST a hook event using the same wire contract as the hook scripts.

    ``max_retries`` defaults to a single attempt: session-start discovery runs inside
    the agent's hook budget, so waiting out a backoff there would cost more than the
    event is worth. One-shot callers such as ``guard install`` can opt into retries, either a
    plain attempt count or a time-bounded ``retry_policy``.
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
            "cli_version": version_info,
        },
        separators=(",", ":"),
    )
    encoded_payload = base64.b64encode(payload.encode()).decode()
    body = f"base64:{encoded_payload}".encode()
    if not base_url.lower().startswith(("http://", "https://")):
        # Match curl's handling in the hook scripts: a URL without a scheme defaults to HTTP.
        base_url = f"http://{base_url}"
    url = f"{base_url.rstrip('/')}{client.endpoint}?version={HOOK_VERSION}"
    headers = {
        "User-Agent": f"snyk/agent-scan Agent Scan v{version_info}",
        "X-User": x_user,
        "Content-Type": "text/plain",
        "X-Client-Id": push_key,
    }
    surface = agent_surface(hook_client)
    if surface:
        headers[AGENT_SURFACE_HEADER] = surface

    try:
        return asyncio.run(_post_hook_event(url, body, headers, max_retries, retry_policy))
    except Exception as error:
        # Delivery is best-effort; never let it break the caller.
        return False, str(error)
