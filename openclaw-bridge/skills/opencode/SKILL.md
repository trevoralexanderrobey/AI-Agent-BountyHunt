---
name: opencode
description: "OpenCode session skill for local coding-agent execution via the OpenCode daemon bridge."
metadata:
  {
    "openclaw":
      {
        "emoji": "🛠️",
        "requires": { "bins": ["node", "opencode"] },
      },
  }
---

# OpenCode Skill

This skill proxies OpenCode daemon session operations through the local OpenClaw runtime.

## Tools

- `opencode_session_create`
- `opencode_session_message`
- `opencode_session_state`
- `opencode_session_close`

## Environment

- `OPENCODE_DAEMON_BASE_URL` (default `http://127.0.0.1:8091`)
