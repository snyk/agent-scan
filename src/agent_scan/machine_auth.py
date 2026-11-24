"""Machine identity auth for the Cerberus tenant routes.

The ADS installer enrolls the machine and passes Agent Scan the installer's
token command and the tenant id (``--token-command``, ``--tenant-id``). The
Snyk API is the scheme and host of ``--analysis-url``, the gateway that serves
the push-key routes too. ``<token command> token --base-url <api>`` prints a
machine access token for that API on stdout, which authenticates
``/hidden/tenants/{tenant_id}/...`` as a bearer token. The token is never
logged and never put on a command line.

Both values set is machine mode. Otherwise the scan uses the push key. Once in
machine mode, a token command that fails is an error, and the scan never falls
back to the push key.
"""

import logging
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from urllib.parse import quote

logger = logging.getLogger(__name__)

# The version the gateway publishes the tenant routes at. It selects the
# OpenAPI document, not the request schema.
TENANT_API_VERSION = "2024-10-15"

# How long one run of the token command may take before the scan fails. The
# command prints a cached token, or refreshes it over the network first. The
# installer bounds that refresh to a minute, so this leaves headroom for process
# start-up on top of a refresh that uses its full minute.
TOKEN_COMMAND_TIMEOUT_S = 90

# Synchronous analysis has no tenant route, so machine mode cannot run it.
SYNC_ANALYSIS_ERROR = (
    "Synchronous analysis has no machine identity route. Enable asynchronous analysis for the tenant, "
    "and do not use --show-analysis-results or --ci."
)


class MachineAuthError(RuntimeError):
    """Machine identity is configured but cannot be used. The caller fails; it never uses the push key instead."""


@dataclass(frozen=True)
class MachineAuth:
    """A machine access token for one tenant on one Snyk API."""

    base_url: str
    tenant_id: str
    access_token: str = field(repr=False)
    # Runs again in ``refresh`` before a late request; empty means the token cannot be refreshed.
    token_command: str = field(default="", repr=False, compare=False)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def tenant_path(self, path: str) -> str:
        """``{base_url}/hidden/tenants/{tenant_id}{path}``, without a query."""
        tenant = quote(self.tenant_id, safe="")
        return f"{self.base_url.rstrip('/')}/hidden/tenants/{tenant}{path}"

    def tenant_url(self, path: str) -> str:
        """``tenant_path`` with the tenant API version query."""
        return f"{self.tenant_path(path)}?version={TENANT_API_VERSION}"

    def refresh(self) -> "MachineAuth":
        """The same auth with a token from running the token command again.

        The token command only guarantees a few minutes of validity, and a scan
        can run longer, so the async submit at the end asks for a fresh token.
        The command prints its cached token while that is still valid. Raises
        MachineAuthError when the command fails.
        """
        if not self.token_command:
            return self
        token = fetch_access_token(self.token_command, self.base_url)
        return replace(self, access_token=token)


def is_machine_mode(values: Sequence[str | None]) -> bool:
    """True when every machine identity value is set. Otherwise the scan uses the push key."""
    return all(value and value.strip() for value in values)


def fetch_access_token(token_command: str, base_url: str, *, timeout: float = TOKEN_COMMAND_TIMEOUT_S) -> str:
    """Run ``<token_command> token --base-url <base_url>`` and return the access token it prints.

    The token command refuses a base URL other than the API the machine enrolled
    with, so a token is never minted for one API and sent to another.

    Raises MachineAuthError when the command cannot run, fails, times out or
    prints anything other than one token. The message holds neither stdout, where
    the token would be, nor stderr, which may echo credentials.
    """
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        completed = subprocess.run(
            [token_command, "token", "--base-url", base_url],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        raise MachineAuthError(f"The token command did not finish within {timeout:g}s.") from None
    except (OSError, ValueError) as e:
        raise MachineAuthError(f"The token command could not run: {e}") from None
    if completed.returncode != 0:
        raise MachineAuthError(f"The token command exited with {completed.returncode}.")
    token = (completed.stdout or "").strip()
    if not token or any(c.isspace() for c in token):
        raise MachineAuthError("The token command did not print a single access token.")
    return token


def resolve_machine_auth(
    token_command: str | None,
    tenant_id: str | None,
    base_url: str,
) -> MachineAuth | None:
    """Machine auth for ``base_url`` when the token command and tenant id are both set, else None (push-key mode).

    Runs the token command once. Raises MachineAuthError when the token command
    is not an absolute path or fails.
    """
    if not is_machine_mode((token_command, tenant_id)):
        return None
    assert token_command and tenant_id
    token_command = token_command.strip()
    if not os.path.isabs(token_command):
        # A bare name is looked up in PATH, and on Windows in the current directory too.
        raise MachineAuthError("The token command must be an absolute path.")
    base_url = base_url.strip()
    token = fetch_access_token(token_command, base_url)
    return MachineAuth(
        base_url=base_url,
        tenant_id=tenant_id.strip(),
        access_token=token,
        token_command=token_command,
    )
