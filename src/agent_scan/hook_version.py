"""Shared hook / API line version (override with HOOK_VERSION in the environment)."""

import os

_DEFAULT = "2025-11-11"
HOOK_VERSION: str = os.environ.get("HOOK_VERSION", _DEFAULT)
