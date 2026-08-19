"""Skill discovery and file-content models.

Contains models for representing skill files during local discovery and analysis.
"""

from pydantic import BaseModel, Field


class DiscoveredSkill(BaseModel):
    """A skill or command found locally and awaiting file collection.

    ``name`` is the local discovery name: the containing directory name for a
    directory skill (for example, ``review`` for ``skills/review/SKILL.md``), or
    the namespaced relative filename for a command (for example, ``git:commit``
    for ``commands/git/commit.md``). It is not read from YAML frontmatter.

    ``path`` points to the content to collect: the skill directory for a
    directory skill, or the Markdown file itself for a single-file command.
    """

    name: str = Field(description="Directory-derived or command-path-derived local discovery name.")
    path: str = Field(
        description="Path to the skill directory or command file, such as '~/.claude/skills/review' "
        "or '~/.claude/commands/git/commit.md'."
    )


class SkillFrontmatter(BaseModel):
    """Validated identity metadata from a directory skill's SKILL.md file."""

    name: str
    description: str


class SkillFile(BaseModel):
    """An individual file collected from a skill directory."""

    path: str = Field(
        description="Relative path of the file within the skill directory (e.g., 'SKILL.md', 'scripts/run.py')."
    )
    content: str = Field(description="Redacted UTF-8 text or a synthetic binary hash marker.")
