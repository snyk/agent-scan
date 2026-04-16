import os
from unittest.mock import patch

from agent_scan.upload import get_hostname


def test_get_hostname_returns_valid_string():
    """Test that get_hostname returns a valid, non-unknown string on all platforms."""
    # Ensure we bypass the CI environment override to test the actual platform.node() call
    with patch("agent_scan.upload.get_environment", return_value="local"):
        hostname = get_hostname()

        assert isinstance(hostname, str)
        assert len(hostname) > 0
        assert hostname != "unknown", "get_hostname() returned 'unknown', which means platform.node() failed"


def test_get_hostname_empty_fallback():
    """Test that get_hostname falls back to 'unknown' if platform.node() returns an empty string."""
    with patch("agent_scan.upload.get_environment", return_value="local"):
        with patch("platform.node", return_value=""):
            hostname = get_hostname()
            assert hostname == "unknown"


def test_get_hostname_ci_override():
    """Test that the CI environment variable override works."""
    with patch("agent_scan.upload.get_environment", return_value="ci"):
        with patch.dict(os.environ, {"AGENT_SCAN_CI_HOSTNAME": "test-ci-host"}):
            hostname = get_hostname()
            assert hostname == "test-ci-host"
