"""
Evaluate Snyk tenant flag `observe-preview` (Observe / Agent Guard eligibility).

Aligned with maverick-ui FEATURE_FLAGS.OBSERVE_PREVIEW and agent-monitor evaluation.
Uses Flipt HTTP API (same contract as invariant-platform backend.utils.featureflags).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

from agent_scan.utils import get_environment

logger = logging.getLogger(__name__)

OBSERVE_PREVIEW_FLAG_KEY = "observe-preview"
DEFAULT_NAMESPACE = "tenant-release"
_FLIPT_EVAL_PATH = "/evaluate/v1/boolean"

FLIPT_URL = os.getenv(
    "FLIPT_URL",
    "http://feature-flags-flipt.feature-flags.svc.cluster.local:8080",
)
_REQUEST_TIMEOUT_SEC = 2


def _skip_flipt_treat_enabled() -> bool:
    """Local/test/dev: no cluster Flipt; behave like invariant-platform local mode."""
    env = get_environment() or "local"
    return env in ("local", "test", "dev")


def is_observe_preview_enabled(tenant_id: str) -> bool:
    """Return True if observe-preview is on for this tenant."""
    tid = tenant_id.strip()
    if not tid:
        return False

    if _skip_flipt_treat_enabled():
        return True

    url = f"{FLIPT_URL.rstrip('/')}{_FLIPT_EVAL_PATH}"
    payload = {
        "namespaceKey": DEFAULT_NAMESPACE,
        "flagKey": OBSERVE_PREVIEW_FLAG_KEY,
        "entityId": tid,
        "context": {"tenant": tid},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SEC) as resp:
            if resp.status != 200:
                logger.warning("flipt_observe_preview_http_status", extra={"status": resp.status})
                return False
            body = json.loads(resp.read().decode("utf-8"))
            return bool(body.get("enabled", False))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        logger.warning("flipt_observe_preview_failed", extra={"error": str(e)})
        return False
