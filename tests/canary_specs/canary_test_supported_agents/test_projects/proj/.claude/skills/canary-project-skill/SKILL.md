---
name: canary-project-skill
description: A committed project-scope skill used by the agent-scan canary to verify that inspect detects skills under <project>/.claude/skills. No claude CLI creates a standalone project skill, so this fixture is the only way to give the scope end-to-end coverage.
---

# canary-project-skill

A dummy project skill. The canary copies this into the registered dummy project and asserts
`agent-scan inspect` reports it at the project-skill scope.
