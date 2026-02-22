Algora-BountyFi Skill
===============

Purpose
- Aggregate and synthesize Algora and Bounty.fi research to provide reconnaissance, prioritized findings, and safe triage suggestions for bounty workflows.

Quickstart
1. Place this skill in your OpenClaw skills directory (e.g., `~/.openclaw/skills/algora-bountyfi`) or register it with your bridge.
2. Ensure `index.js` is executable by Node and that Node is available in the runtime that loads skills.
3. Call the `summarize_research` endpoint with research text payload.

Files
- `SKILL.md` — skill manifest and metadata.
- `index.js` — minimal implementation of handlers.

Notes
- This is a starter scaffold. Extend `index.js` to parse PDFs or other attachments and implement richer summarization logic using local models or the bridge's OpenClaw client.
