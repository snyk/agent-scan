from uuid import uuid4

from agent_scan.runtime_config import RuntimeConfig, get_runtime_config, reset_runtime_config, set_runtime_config


def test_get_runtime_config_returns_default_before_set():
    reset_runtime_config()

    cfg = get_runtime_config()

    assert cfg.scan_event_id is None
    assert cfg.config == {}
    assert cfg.source == "default"


def test_set_runtime_config_round_trips():
    reset_runtime_config()
    scan_event_id = uuid4()
    expected = RuntimeConfig(scan_event_id=scan_event_id, config={"feature": True}, source="bootstrap")

    set_runtime_config(expected)

    assert get_runtime_config() == expected


def test_reset_runtime_config_clears_singleton():
    set_runtime_config(RuntimeConfig(scan_event_id=uuid4(), source="bootstrap"))

    reset_runtime_config()

    assert get_runtime_config().source == "default"
