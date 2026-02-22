# OpenCode Daemon Skill Backend

This daemon exposes a local HTTP API used by the OpenClaw `opencode` skill.

## Endpoints

- `GET /health`
- `POST /session`
- `POST /session/:id/message`
- `GET /session/:id/state`
- `POST /session/:id/close`
- `GET /metrics`

## Runtime model

- Primary backend: persistent `opencode serve` on `127.0.0.1:8090`
- Fallback backend: `opencode run --session <id> --model ollama/openthinker:7b --format json`

## Local run

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills/opencode-daemon"
npm install
npm start
```

## PM2

`/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/ecosystem.config.js` includes an `openclaw-opencode-daemon` app.
