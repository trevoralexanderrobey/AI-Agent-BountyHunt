# Operations Guide (Bridge + MCP + OpenCode Daemon)

This stack runs locally on loopback.
PM2 is the recommended supervisor. LaunchAgents are an optional alternative.

Canonical workspace root:

- `/Users/trevorrobey/AI-Agent-BountyHunt`

## Runtime components

- Bridge API: `http://127.0.0.1:8787`
- MCP server: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/dist/server.js`
- OpenCode daemon: `http://127.0.0.1:8091`
- OpenCode internal server: `http://127.0.0.1:8090`
- Ollama API: `http://localhost:11434/v1`
- Default model: `qwen2.5-coder:7b`

## Start/stop commands

### Bridge

From `openclaw-bridge/`:

```bash
npm run bridge:start
npm run bridge:stop
npm run bridge:restart
npm run bridge:status
npm run bridge:logs
```

### Bridge + MCP + OpenCode daemon (PM2)

From `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/`:

```bash
./scripts/mcp-start-pm2.sh
pm2 status openclaw-bridge openclaw-mcp openclaw-opencode-daemon
pm2 logs openclaw-bridge
pm2 logs openclaw-mcp
pm2 logs openclaw-opencode-daemon
```

`mcp-start-pm2.sh` also syncs repo skill sources in `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills/` to runtime `~/.openclaw/skills/`, and starts `openclaw-bridge` from `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/bridge-ecosystem.config.js`.

## LaunchAgent install (macOS)

From `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/`:

```bash
./scripts/mcp-install-launchd.sh
```

This generates:

- `~/Library/LaunchAgents/com.openclaw.mcp.plist`
- `~/Library/LaunchAgents/com.openclaw.opencode-daemon.plist`
- `~/Library/LaunchAgents/com.openclaw.bridge.plist`

Use one supervisor at a time for these services (PM2 or LaunchAgents, not both).

## Local env file

Primary local env file:

- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/.env`

Key variables:

- `OPENCLAW_GATEWAY_BASE_URL=http://localhost:11434/v1`
- `OPENCLAW_DEFAULT_MODEL=qwen2.5-coder:7b`
- `OPENCLAW_BRIDGE_BASE_URL=http://127.0.0.1:8787`
- `BIONICLINK_BASE_URL=https://127.0.0.1:8090`
- `OPENCODE_SERVER_BASE_URL=http://127.0.0.1:8090`
- `OPENCODE_DAEMON_BASE_URL=http://127.0.0.1:8091`
- `OPENCODE_DAEMON_PORT=8091`
- `OPENCODE_SERVER_PORT=8090`
- `OPENCODE_MAX_ACTIVE_SESSIONS=2`
- `OPENCODE_QUEUE_MAX=8`
- `MCP_SSE_KEEPALIVE_MS=15000` (optional; keepalive interval for `/mcp/sse`)

Optional provider multiplexing:

- `OPENCLAW_<PROVIDER>_BASE_URL` (for provider-prefixed model routing)
- `OPENCLAW_<PROVIDER>_API_KEY`
- Example provider model prefixes: `qwen:qwen3-32b` or `qwen/qwen3-32b`

## Verification

Run:

```bash
pm2 status openclaw-bridge openclaw-mcp openclaw-opencode-daemon
curl -sS http://127.0.0.1:8787/health | jq
curl -sS http://127.0.0.1:8091/health | jq
curl -sS http://127.0.0.1:8091/metrics
curl -sS http://localhost:11434/v1/models | jq
curl -N --max-time 5 http://127.0.0.1:8787/mcp/sse
```

If `BRIDGE_AUTH_TOKEN` is configured:

```bash
curl -N -H "Authorization: Bearer $BRIDGE_AUTH_TOKEN" http://127.0.0.1:8787/mcp/sse
```

## Recovery notes

- If `openclaw-opencode-daemon` fails repeatedly, inspect PM2 logs and verify `opencode --version`.
- If `execute_skill_tool` fails for `skill=opencode`, run `openclaw-bridge/scripts/sync-skill-to-runtime.sh` and restart MCP.
- If Ollama model errors occur, verify `ollama list` includes `qwen2.5-coder:7b`.

## Security

- Keep all services bound to `127.0.0.1`.
- Keep `.env` local and out of git.
- Keep active-scan gates disabled unless intentionally testing.

## Workspace boundary

Treat `/Users/trevorrobey/AI-Agent-BountyHunt` as the active runtime workspace root for this stack.
