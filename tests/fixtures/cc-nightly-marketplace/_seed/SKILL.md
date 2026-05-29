---
name: nightly-seed-skill
description: Template SKILL.md copied into ~/.claude/skills and <workspace>/.claude/skills by the nightly CircleCI workflow so agent-scan global- and project-scope skill discovery has something to find. Has no runtime behaviour.
---

Placeholder skill used by the nightly Claude Code x agent-scan CircleCI
workflow. The job copies this file into the global and project skill
directories at run time; the `name:` front-matter is overwritten by the
job's `mkdir` step (folder name becomes the skill name) so this template
can be reused for both scopes.
