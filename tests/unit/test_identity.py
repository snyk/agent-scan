"""Tests for agent_scan.identity — the local push-key store used by guard login."""

from __future__ import annotations

import stat
import sys

import pytest

from agent_scan import identity


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "identity.json"
    identity.save_identity(
        push_key="pk-abc123",
        tenant_id="t-1",
        url="https://api.snyk.io",
        default_profile="standard",
        hostname="host-1",
        path=path,
    )
    loaded = identity.load_identity(path)
    assert loaded == {
        "push_key": "pk-abc123",
        "tenant_id": "t-1",
        "url": "https://api.snyk.io",
        "default_profile": "standard",
        "hostname": "host-1",
    }


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode")
def test_saved_file_is_user_only(tmp_path):
    path = tmp_path / "identity.json"
    identity.save_identity("pk", "t", "u", "strict", "h", path=path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_load_missing_returns_none(tmp_path):
    assert identity.load_identity(tmp_path / "absent.json") is None


def test_load_corrupt_returns_none(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text("{ not json")
    assert identity.load_identity(path) is None
