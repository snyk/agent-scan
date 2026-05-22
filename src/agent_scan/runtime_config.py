from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RuntimeConfig(BaseModel):
    # frozen=True blocks field reassignment (`cfg.bootstrap_event_id = ...`); the
    # `config` dict is still a mutable object, so the accessors below take a
    # deep copy on store and on read to keep the singleton fully owned.
    model_config = ConfigDict(frozen=True)

    bootstrap_event_id: UUID | None = None
    # Server-delivered runtime config. Known keys consumed today:
    #   - "skip_servers": list[str] — see `matched_skip_needle` below.
    config: dict[str, Any] = Field(default_factory=dict)
    source: Literal["bootstrap", "default"] = "default"

    def matched_skip_needle(self, server_name: str, server: Any) -> str | None:
        """Return the matched skip needle if server should be skipped.

        Substring match against a haystack built from the server's name and
        its connection details (command + args for stdio, url for remote).
        """
        needles = self.config.get("skip_servers")
        if not isinstance(needles, list) or not needles:
            return None
        parts: list[str] = [server_name]
        cmd = getattr(server, "command", None)
        if cmd:
            parts.append(cmd)
        args = getattr(server, "args", None) or []
        parts.extend(str(a) for a in args)
        url = getattr(server, "url", None)
        if url:
            parts.append(url)
        haystack = " ".join(parts)
        return next(
            (n for n in needles if isinstance(n, str) and n and n in haystack),
            None,
        )


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
