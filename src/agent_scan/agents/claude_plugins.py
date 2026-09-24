"""Shared Claude Code and Desktop plugin skills and MCP discovery."""

import logging
from abc import abstractmethod
from functools import partial
from pathlib import Path

from pydantic import field_validator, model_validator

from agent_scan.agents.base import (
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
    _escapes_plugin_root,
    _walk_manifest_candidates,
    _walk_under_depth,
)
from agent_scan.models import (
    SERVER_CONFIG_DISCRIMINATOR_KEYS,
    ClaudeConfigFile,
    MCPConfig,
    PluginMCPConfigFile,
)
from agent_scan.skill_client import inspect_skills_dir

logger = logging.getLogger(__name__)

_CLAUDE_MCP_FORMATS: tuple[type[MCPConfig], ...] = (ClaudeConfigFile, PluginMCPConfigFile)


def _configured_plugin_servers(servers: object) -> object:
    if not isinstance(servers, dict):
        return servers
    result = {}
    for name, server in servers.items():
        if (
            isinstance(server, dict)
            and server.get("type") in ("http", "sse", "streamable-http", "streamable-https")
            and not any(key in server for key in SERVER_CONFIG_DISCRIMINATOR_KEYS)
        ):
            # Desktop plugins can declare connectors without a configured endpoint.
            logger.debug("Skipping plugin connector without an endpoint")
            continue
        result[name] = server
    return result


class _WrappedPluginConfig(ClaudeConfigFile):
    @field_validator("mcpServers", mode="before")
    @classmethod
    def configured_servers(cls, value: object) -> object:
        return _configured_plugin_servers(value)


class _FlatPluginConfig(PluginMCPConfigFile):
    @model_validator(mode="before")
    @classmethod
    def wrap_flat_dict(cls, data: object) -> object:
        filtered = _configured_plugin_servers(data)
        if isinstance(data, dict) and data and filtered == {}:
            return {"servers": {}}
        return super().wrap_flat_dict(filtered)


class ClaudePluginDiscoverer(AgentDiscoverer, abstract=True):
    """Share plugin parsing while each client supplies its own installation roots."""

    _plugin_manifest_dirs = (".claude-plugin", ".codex-plugin", ".cursor-plugin")
    _confine_plugin_paths = False

    def __init__(self, home_directory: Path | None, target_folders: list[Path] | None = None) -> None:
        super().__init__(home_directory, target_folders)
        self._plugin_manifests_cache: list[tuple[Path, dict]] | None = None

    @abstractmethod
    def _plugin_base_dirs(self) -> list[Path]:
        """Return this client's installed plugin roots."""

    def _plugin_path_allowed(self, path: Path, root: Path) -> bool:
        if not self._confine_plugin_paths:
            return True
        try:
            return path.resolve().is_relative_to(root.resolve())
        except (OSError, RuntimeError, ValueError):
            return False

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for base in self._plugin_base_dirs():
            for path in _walk_under_depth(base, ".mcp.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not self._plugin_path_allowed(path, base):
                    continue
                try:
                    if not path.is_file():
                        continue
                except (OSError, ValueError):
                    continue
                parsed = self._parse_mcp_file(path, formats=(_WrappedPluginConfig, _FlatPluginConfig))
                if parsed:
                    result[path.as_posix()] = parsed
        return result

    def _scan_plugin_skills_dir(self, path: Path, root: Path) -> SkillsDirsResult:
        if not self._plugin_path_allowed(path, root):
            return {}
        inspect_fn = (
            partial(inspect_skills_dir, boundary=str(root)) if self._confine_plugin_paths else inspect_skills_dir
        )
        entries = self._scan_skills_dir(path, inspect_fn)
        return {path.as_posix(): entries} if entries is not None else {}

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for base in self._plugin_base_dirs():
            for path in _walk_under_depth(base, "skills", _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                result.update(self._scan_plugin_skills_dir(path, base))
        return result

    def _plugin_manifests(self) -> list[tuple[Path, dict]]:
        if self._plugin_manifests_cache is not None:
            return self._plugin_manifests_cache
        manifests: list[tuple[Path, dict]] = []
        for base in self._plugin_base_dirs():
            for manifest in _walk_manifest_candidates(
                base, "plugin.json", self._plugin_manifest_dirs, _MAX_PLUGIN_RGLOB_DEPTH
            ):
                if self._confine_plugin_paths and manifest.parent.name not in self._plugin_manifest_dirs:
                    continue
                if not self._plugin_path_allowed(manifest, base):
                    continue
                data = self._load_json_file(manifest, log_parse_errors=False)
                if isinstance(data, dict):
                    manifests.append((manifest, data))
        self._plugin_manifests_cache = manifests
        return manifests

    def _discover_plugin_manifest_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for manifest, data in self._plugin_manifests():
            inline = _configured_plugin_servers(data.get("mcpServers"))
            if isinstance(inline, dict) and inline:
                result[manifest.as_posix()] = self._validate_servers(
                    inline, source=f"plugin manifest {manifest.as_posix()}"
                )
        return result

    def _discover_plugin_manifest_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for manifest, data in self._plugin_manifests():
            skills = data.get("skills")
            if not isinstance(skills, list):
                continue
            plugin_root = manifest.parent.parent
            for rel in skills:
                if not isinstance(rel, str) or not rel.strip() or _escapes_plugin_root(rel.strip()):
                    continue
                result.update(self._scan_plugin_skills_dir(plugin_root / rel.strip(), plugin_root))
        return result
