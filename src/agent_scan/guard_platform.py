"""Installation-time OS family and process architecture for fleet reporting."""

import os
import struct
import sys
import sysconfig


def collect_platform() -> dict[str, str]:
    """Keep each recognized field independently; a 32-bit process has no fleet arch."""
    fields = {}
    family = {"linux": "Linux", "darwin": "Darwin", "win32": "Windows"}.get(sys.platform)
    if family:
        fields["os"] = family
    if struct.calcsize("P") != 8:
        return fields

    if sys.platform == "win32":
        target = sysconfig.get_platform().removeprefix("win-")
    else:
        # Linux uname may describe the host kernel. Prefer the Python build target.
        target = getattr(sys.implementation, "_multiarch", "").split("-")[0] if sys.platform == "linux" else ""
        if not target:
            try:
                target = os.uname().machine
            except (AttributeError, OSError):
                return fields
    arch = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(target.lower())
    if arch:
        fields["arch"] = arch
    return fields
