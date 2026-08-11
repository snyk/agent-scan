"""Skill location and file-content models.

Contains models for representing skill files during local discovery and analysis.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SkillServer(BaseModel):
    """Legacy skill representation model.

    In the legacy v2025-09-02 scan pipeline, skills were wrapped as a server variant
    under ``ServerScanResult.server`` alongside ``StdioServer`` and ``RemoteServer``.
    Maintained for local discovery and backward compatibility; will be deprecated as
    callers migrate fully to ``SkillRequest`` and ``SkillFile``.
    """

    model_config = ConfigDict()
    path: str
    type: Literal["skill"] | None = "skill"


class SkillFile(BaseModel):
    """New model representing an individual file inside a Skill directory.

    Used by ``SkillRequest`` in the v2026-07-10 API contract to send relative file paths
    and raw file contents to the backend for analysis.
    """

    path: str = Field(
        description="Relative path of the file within the skill directory (e.g., 'SKILL.md', 'scripts/run.py')."
    )
    content: str = Field(description="Raw UTF-8 text content of the file.")
