---
name: nightly-plugin-skill
description: Plugin-scope skill used by the agent-scan nightly CircleCI workflow to verify that discovery picks up skills bundled inside an installed plugin. Has no runtime behaviour.
---

This skill exists only so the nightly CircleCI workflow can confirm that
`agent-scan` discovers plugin-scope skills under
`~/.claude/plugins/cache/**/skills/`. It is intentionally inert.
