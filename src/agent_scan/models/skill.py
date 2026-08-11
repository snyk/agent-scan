"""Skill location and file-content models.

Contains models for representing skill files during local discovery and analysis.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SkillServer(BaseModel):
    """A discovered skill location awaiting file collection."""

    model_config = ConfigDict()
    path: str
    type: Literal["skill"] | None = "skill"


class SkillFile(BaseModel):
    """An individual file collected from a skill directory."""

    path: str = Field(
        description="Relative path of the file within the skill directory (e.g., 'SKILL.md', 'scripts/run.py')."
    )
    content: str = Field(description="Raw UTF-8 text content of the file.")
