"""Test-only helpers for synthesizing fake high-entropy credentials.

Redaction tests need a value that detect-secrets flags as a secret, but checking
a static high-entropy literal into the repo trips secret scanners (e.g.
GitGuardian). These helpers derive such a value at runtime instead.
"""

import base64
import hashlib


def synthetic_secret(seed: bytes = b"agent-scan synthetic test credential") -> str:
    """Return a reproducible, high-entropy alphanumeric token for redaction tests.

    Derived from a SHA-256 of ``seed`` (base64-encoded, alphanumerics only) so it
    trips detect-secrets' Base64HighEntropyString plugin in both quoted and
    unquoted contexts, without being a hardcoded secret literal.
    """
    encoded = base64.b64encode(hashlib.sha256(seed).digest()).decode()
    return "".join(c for c in encoded if c.isalnum())
