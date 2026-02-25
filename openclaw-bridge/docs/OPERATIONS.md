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

## Skill Spawner (generate new skills)

Generate new tool skills using the Master Skill Spawner:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"

# Generate a CLI skill
python3 scripts/spawner.py nmap --flags "-sV -sC"

# Dry-run (preview only)
python3 scripts/spawner.py dirb --dry-run

# Overwrite existing skill
python3 scripts/spawner.py nmap --force
```

Generated skills are placed in `skills/<slug>/` and auto-synced to `~/.openclaw/skills/`.

Each generated skill includes the full Skill Runtime v1 interface:
- **Execution**: `run()`, `health()` \u2014 Docker-wrapped tool execution with redaction
- **Forensics**: `read_output_chunk()`, `search_output()` \u2014 lossless output retrieval
- **Analysis**: `semantic_summary()`, `anomaly_summary()`, `anomaly_diff()` \u2014 automated analysis
- **Baseline**: `tag_baseline()`, `list_baselines()`, `diff_against_baseline()` \u2014 golden image comparison

Runtime spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/skill-runtime-v1.md`

## MCP Skill Containers (distributed execution)

Build and run skills as isolated Docker containers with JSON-RPC MCP transport:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"

# Build containerized nmap skill
docker build -f containers/nmap/Dockerfile -t openclaw-nmap-skill .

# Run with hardened security
docker run -d -p 4000:4000 --cap-drop ALL --name nmap-skill \
  -e MCP_SKILL_TOKEN=your_token -e TOOL_NAME=nmap -e SKILL_SLUG=nmap \
  openclaw-nmap-skill

# Health check
curl -sS http://127.0.0.1:4000/mcp \
  -H 'Authorization: Bearer your_token' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"health","params":{},"id":"h1"}'
```

Spawner v2 automates container lifecycle (network creation, spawn with health probing, terminate, orphan cleanup):

```bash
# Validate Spawner v2 API
node -e "const { createSpawnerV2 } = require('./spawner/spawner-v2.js'); console.log(Object.keys(createSpawnerV2()));"

# List running skill containers
docker ps --filter name=openclaw-skill-
```

Specs:
- Container spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/mcp-skill-container-spec.md`
- Spawner v2 spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/spawner-v2-spec.md`

## Supervisor v1 (routing and pooling)

Supervisor v1 provides deterministic routing and connection pooling over Spawner v2:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"

# Validate Supervisor v1 API
node -e "const { createSupervisorV1 } = require('./supervisor/supervisor-v1.js'); console.log(Object.keys(createSupervisorV1()));"

# Initialize and execute
node -e "(async()=>{
  const { createSupervisorV1 } = require('./supervisor/supervisor-v1.js');
  const sv = createSupervisorV1();
  await sv.initialize();
  console.log(await sv.execute('nmap', 'health', {}));
  console.log(await sv.getStatus());
  await sv.shutdown();
})().catch(console.error)"
```

Key behaviors:
- Routes to oldest idle READY instance, spawns on-demand if under `maxInstances`
- Rejects at capacity (`SUPERVISOR_CAPACITY_EXCEEDED`)
- `reapIdle()` terminates instances idle beyond `idleTTLms` (default 60s)
- `shutdown()` gracefully terminates all pooled instances

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/supervisor-v1-spec.md`

## Observability (telemetry)

In-memory metrics for Supervisor and Spawner. No external exporters or file I/O:

```bash
# Access metrics snapshot via Supervisor
node -e "(async()=>{
  const { createSupervisorV1 } = require('./supervisor/supervisor-v1.js');
  const sv = createSupervisorV1();
  await sv.initialize();
  console.log(JSON.stringify(sv.getMetrics(), null, 2));
  await sv.shutdown();
})().catch(console.error)"
```

Namespaces: `supervisor.*` (routing/pool metrics) and `spawner.*` (container lifecycle metrics).

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/observability-spec.md`

## Security baseline (Phase 9)

Auth and rate limiting for the Supervisor ingress:

```bash
# Enable auth (set token via env)
export SUPERVISOR_AUTH_ENABLED=true
export SUPERVISOR_AUTH_TOKEN=your_secure_token

# Enable rate limiting
export SUPERVISOR_RATE_LIMIT_ENABLED=true
export SUPERVISOR_RATE_LIMIT_RPS=10
export SUPERVISOR_RATE_LIMIT_BURST=20
```

Key controls:
- **Auth guard**: Constant-time bearer token validation (`crypto.timingSafeEqual`)
- **Rate limiter**: Per-caller in-memory token bucket (O(1), no locks)
- **Request ID**: Auto-generated at `execute()`, propagated through MCP, Spawner, metrics, and errors
- No hardcoded credentials; env-first configuration

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/phase-9-security-baseline.md`
