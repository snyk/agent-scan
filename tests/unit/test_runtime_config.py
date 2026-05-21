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
