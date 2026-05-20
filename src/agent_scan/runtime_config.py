from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RuntimeConfig(BaseModel):
    # frozen=True blocks field reassignment (`cfg.bootstrap_event_id = ...`); the
    # `config` dict is still a mutable object, so the accessors below take a
    # deep copy on store and on read to keep the singleton fully owned.
    model_config = ConfigDict(frozen=True)

    bootstrap_event_id: UUID | None = None
    # TODO: plumbing only — populated from ClientBootstrapResponse.runtime_config
    # but not yet read by any client code. See the TODO on
    # ClientBootstrapResponse.runtime_config in agent_scan/models.py for the
    # follow-up that will start consuming specific keys.
    config: dict[str, Any] = Field(default_factory=dict)
    source: Literal["bootstrap", "default"] = "default"


_runtime_config: RuntimeConfig | None = None


def set_runtime_config(cfg: RuntimeConfig) -> None:
    """Store ``cfg`` as the process-wide singleton.

    A deep copy is taken so a caller that later mutates ``cfg.config`` does
    not silently mutate the stored state.
    """
    global _runtime_config
    _runtime_config = cfg.model_copy(deep=True)


def get_runtime_config() -> RuntimeConfig:
    """Return the current runtime config, or a fresh default if unset.

    The returned value is a deep copy: mutating ``.config`` on it will not
    affect the singleton, so the singleton cannot become an unintended
    holder of caller-side state for the lifetime of the process.
    """
    if _runtime_config is None:
        return RuntimeConfig()
    return _runtime_config.model_copy(deep=True)


def reset_runtime_config() -> None:
    global _runtime_config
    _runtime_config = None
