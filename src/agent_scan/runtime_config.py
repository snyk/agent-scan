from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# [REVIEW-COMMENT]
# Added a process-local runtime config so the bootstrap response can be shared
# with later upload calls without threading a new argument through every scan
# pipeline layer.
# [/REVIEW-COMMENT]
class RuntimeConfig(BaseModel):
    scan_event_id: UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    source: Literal["bootstrap", "default"] = "default"


# [REVIEW-COMMENT]
# Keep the singleton behind small accessors so commands that skip or fail
# bootstrap can reset to safe defaults and tests can isolate process state.
# [/REVIEW-COMMENT]
_runtime_config: RuntimeConfig | None = None


def set_runtime_config(cfg: RuntimeConfig) -> None:
    global _runtime_config
    _runtime_config = cfg


def get_runtime_config() -> RuntimeConfig:
    if _runtime_config is None:
        return RuntimeConfig()
    return _runtime_config


def reset_runtime_config() -> None:
    global _runtime_config
    _runtime_config = None
