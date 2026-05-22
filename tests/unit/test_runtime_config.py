from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agent_scan.runtime_config import RuntimeConfig, get_runtime_config, reset_runtime_config, set_runtime_config


def test_get_runtime_config_returns_default_before_set():
    cfg = get_runtime_config()

    assert cfg.bootstrap_event_id is None
    assert cfg.config == {}
    assert cfg.source == "default"


def test_set_runtime_config_round_trips():
    bootstrap_event_id = uuid4()
    expected = RuntimeConfig(bootstrap_event_id=bootstrap_event_id, config={"feature": True}, source="bootstrap")

    set_runtime_config(expected)

    assert get_runtime_config() == expected


def test_reset_runtime_config_clears_singleton():
    set_runtime_config(RuntimeConfig(bootstrap_event_id=uuid4(), source="bootstrap"))

    reset_runtime_config()

    assert get_runtime_config().source == "default"


# The next two tests deliberately mutate the singleton without resetting it
# themselves. They rely on the autouse `_reset_runtime_config` fixture in
# tests/conftest.py to clear state between tests. If that fixture is removed
# or stops firing, one of these tests will fail depending on collection
# order — making the regression loud rather than silent.
def test_autouse_fixture_isolates_mutated_state_first():
    set_runtime_config(RuntimeConfig(bootstrap_event_id=uuid4(), source="bootstrap"))

    assert get_runtime_config().source == "bootstrap"


def test_autouse_fixture_isolates_mutated_state_second():
    assert get_runtime_config().source == "default"
    assert get_runtime_config().bootstrap_event_id is None


def test_runtime_config_field_assignment_is_blocked():
    """Reassigning a field on a RuntimeConfig must raise — the model is frozen."""
    cfg = RuntimeConfig()
    with pytest.raises(ValidationError):
        cfg.bootstrap_event_id = uuid4()


def test_mutating_returned_config_dict_does_not_affect_singleton():
    """A caller mutating ``.config`` on the returned instance must not bleed into the singleton."""
    set_runtime_config(RuntimeConfig(config={"feature": True}, source="bootstrap"))

    leaked = get_runtime_config()
    leaked.config["feature"] = "TAMPERED"
    leaked.config["new_key"] = "added"

    fresh = get_runtime_config()
    assert fresh.config == {"feature": True}
    assert "new_key" not in fresh.config


def test_mutating_caller_side_config_dict_after_set_does_not_affect_singleton():
    """The dict the caller passed in must not remain shared with the singleton."""
    shared = {"feature": True}
    set_runtime_config(RuntimeConfig(config=shared, source="bootstrap"))

    shared["feature"] = "TAMPERED"
    shared["new_key"] = "added"

    stored = get_runtime_config()
    assert stored.config == {"feature": True}
    assert "new_key" not in stored.config


def test_get_runtime_config_returns_independent_instances():
    """Two ``get_runtime_config()`` calls must return distinct dict objects so per-call mutation cannot bleed across consumers."""
    set_runtime_config(RuntimeConfig(config={"feature": True}, source="bootstrap"))

    first = get_runtime_config()
    second = get_runtime_config()

    assert first == second
    assert first.config is not second.config


class _StdioLike:
    """Minimal duck-type stand-in for StdioServer in matcher tests.

    Using a structural stand-in (rather than the real StdioServer) keeps
    these tests honest about what matched_skip_needle actually reads:
    only ``command`` and ``args``. If the matcher is ever changed to peek
    at additional attributes, these tests will not silently start passing
    for the wrong reason.
    """

    def __init__(self, command: str | None = None, args: list[str] | None = None):
        self.command = command
        self.args = args or []


class _RemoteLike:
    def __init__(self, url: str | None = None):
        self.url = url


def test_matched_skip_needle_returns_none_when_skip_servers_missing():
    cfg = RuntimeConfig(config={})

    assert cfg.matched_skip_needle("entra-mcp-proxy", _StdioLike("uvx", ["entra-mcp-proxy"])) is None


def test_matched_skip_needle_returns_none_when_skip_servers_empty():
    cfg = RuntimeConfig(config={"skip_servers": []})

    assert cfg.matched_skip_needle("entra-mcp-proxy", _StdioLike("uvx", ["entra-mcp-proxy"])) is None


def test_matched_skip_needle_returns_none_when_skip_servers_wrong_type():
    """A non-list ``skip_servers`` must not raise — degrade to no-match."""
    cfg = RuntimeConfig(config={"skip_servers": "entra-mcp-proxy"})

    assert cfg.matched_skip_needle("entra-mcp-proxy", _StdioLike("uvx", ["entra-mcp-proxy"])) is None


def test_matched_skip_needle_matches_on_server_name():
    cfg = RuntimeConfig(config={"skip_servers": ["entra-mcp-proxy"]})

    assert cfg.matched_skip_needle("entra-mcp-proxy", _StdioLike("uvx", [])) == "entra-mcp-proxy"


def test_matched_skip_needle_matches_on_command():
    cfg = RuntimeConfig(config={"skip_servers": ["my-binary"]})

    assert cfg.matched_skip_needle("anon", _StdioLike("/usr/local/bin/my-binary", [])) == "my-binary"


def test_matched_skip_needle_matches_on_args_substring():
    """The EagleView shape: name carries no useful identifier, the match
    must come from the args (here the git repo URL fragment)."""
    cfg = RuntimeConfig(config={"skip_servers": ["entra-mcp-proxy"]})
    server = _StdioLike(
        "uvx",
        [
            "--from",
            "git+ssh://github.eagleview.com/infrastructure/entra-mcp-proxy.git",
            "entra-mcp-proxy",
        ],
    )

    assert cfg.matched_skip_needle("anon", server) == "entra-mcp-proxy"


def test_matched_skip_needle_matches_remote_url():
    cfg = RuntimeConfig(config={"skip_servers": ["internal.example.com"]})
    server = _RemoteLike(url="https://internal.example.com/mcp")

    assert cfg.matched_skip_needle("remote", server) == "internal.example.com"


def test_matched_skip_needle_ignores_empty_and_non_string_needles():
    """Empty strings would substring-match everything; non-strings would crash.
    Both must be silently filtered, not surface as runtime errors."""
    cfg = RuntimeConfig(config={"skip_servers": ["", None, 42, "good"]})
    server = _StdioLike("uvx", ["good"])

    assert cfg.matched_skip_needle("anon", server) == "good"


def test_matched_skip_needle_returns_none_when_no_needle_matches():
    cfg = RuntimeConfig(config={"skip_servers": ["nothing-matches"]})

    assert cfg.matched_skip_needle("entra", _StdioLike("uvx", ["other"])) is None


def test_matched_skip_needle_does_not_read_env():
    """Env values can carry secrets and may legitimately contain skip needles
    (e.g. a redacted marker, a token name). They must not influence routing."""
    cfg = RuntimeConfig(config={"skip_servers": ["secret-value"]})

    server = SimpleNamespace(
        command="uvx",
        args=["safe-server"],
        env={"TOKEN": "secret-value"},
    )

    assert cfg.matched_skip_needle("safe-server", server) is None


def test_matched_skip_needle_returns_first_match_when_multiple_could_match():
    """Document the ordering guarantee: needles are checked in declared order.
    Callers log the returned needle, so a stable answer matters for triage."""
    cfg = RuntimeConfig(config={"skip_servers": ["uvx", "entra"]})
    server = _StdioLike("uvx", ["entra-mcp-proxy"])

    assert cfg.matched_skip_needle("anon", server) == "uvx"
