"""Machine identity auth for the Cerberus tenant routes.

The ADS installer enrolls the machine and passes Agent Scan the installer's
token command, the tenant id and the Snyk API base URL (``--token-command``,
``--tenant-id``, ``--base-url``). ``<token command> token --base-url <base url>``
prints a machine access token for that API on stdout, which authenticates
``/hidden/tenants/{tenant_id}/...`` as a bearer token. The token is never
logged and never put on a command line.

The installer decides the auth type up front: all three values set is machine
mode, none of them set is push-key mode. Some but not all of them is a
configuration error, and a token command that fails is an error too. Neither
falls back to the push key.
"""

import logging
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
# command prints a cached token, or refreshes it over the network first (the
# installer bounds that refresh to a minute).
TOKEN_COMMAND_TIMEOUT_S = 60
# Bounds the token command's error output in our own error message.
_STDERR_EXCERPT_CHARS = 300

_SCAN_VALUE_NAMES = ("--token-command", "--tenant-id", "--base-url")

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


def is_machine_mode(values: Sequence[str | None], names: Sequence[str] = _SCAN_VALUE_NAMES) -> bool:
    """True when every machine identity value is set, False when none is.

    ``names`` label ``values`` in the error. Raises MachineAuthError when only
    some are set: the installer passes all of them or none.
    """
    present = [bool(value and value.strip()) for value in values]
    if not any(present):
        return False
    if all(present):
        return True
    missing = ", ".join(name for name, ok in zip(names, present, strict=True) if not ok)
    raise MachineAuthError(f"Machine identity needs {', '.join(names)} set together; missing: {missing}.")


def fetch_access_token(token_command: str, base_url: str, *, timeout: float = TOKEN_COMMAND_TIMEOUT_S) -> str:
    """Run ``<token_command> token --base-url <base_url>`` and return the access token it prints.

    The token command refuses a base URL other than the API the machine enrolled
    with, so a token is never minted for one API and sent to another.

    Raises MachineAuthError when the command cannot run, fails, times out or
    prints anything other than one token. The message never holds stdout, where
    the token would be.
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
        detail = (completed.stderr or "").strip()[-_STDERR_EXCERPT_CHARS:]
        raise MachineAuthError(
            f"The token command exited with {completed.returncode}{f': {detail}' if detail else '.'}"
        )
    token = (completed.stdout or "").strip()
    if not token or any(c.isspace() for c in token):
        raise MachineAuthError("The token command did not print a single access token.")
    return token


def resolve_machine_auth(
    token_command: str | None,
    tenant_id: str | None,
    base_url: str | None,
) -> MachineAuth | None:
    """Machine auth when all three values are set, None (push-key mode) when none is.

    Runs the token command once. Raises MachineAuthError when only some values
    are set or the token command fails.
    """
    if not is_machine_mode((token_command, tenant_id, base_url)):
        return None
    assert token_command and tenant_id and base_url
    token = fetch_access_token(token_command.strip(), base_url.strip())
    return MachineAuth(
        base_url=base_url.strip(),
        tenant_id=tenant_id.strip(),
        access_token=token,
        token_command=token_command.strip(),
    )
