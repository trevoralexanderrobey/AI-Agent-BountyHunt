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

## HTTP API ingress (Phase 10)

External HTTP layer wrapping Supervisor v1:

```bash
# Start with HTTP ingress enabled
HTTP_SERVER_ENABLED=true HTTP_SERVER_PORT=8080 node http/server.js

# Execute a skill via API
curl -X POST http://127.0.0.1:8080/api/v1/execute \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer your_token' \
  -d '{"slug":"nmap","method":"health","params":{}}'

# Health and metrics
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/metrics
```

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/http-api-spec.md`

## Production hardening (Phase 11)

TLS, request signing, audit logging, and Prometheus:

```bash
# TLS/mTLS
export TLS_ENABLED=true TLS_CERT_PATH=/path/fullchain.pem TLS_KEY_PATH=/path/privkey.pem
export MTLS_ENABLED=true MTLS_CA_PATH=/path/client-ca.pem

# Request signing
export REQUEST_SIGNING_ENABLED=true REQUEST_SIGNING_SECRET=your_hmac_secret

# Audit logging
export AUDIT_LOG_ENABLED=true AUDIT_LOG_PATH=./logs/audit.log

# Prometheus exporter
export PROMETHEUS_EXPORTER_ENABLED=true
curl http://127.0.0.1:8080/metrics/prometheus
```

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/phase-11-production-hardening.md`

## Tool adapters (Phase 11A–11C)

Direct CLI tool execution via standardized adapters (bypass container lifecycle):

Available tools: `curl`, `nslookup`, `whois`, `hashcat`, `sqlmap`, `nikto`

```bash
# Execute a tool adapter via HTTP API
curl -X POST http://127.0.0.1:8080/api/v1/execute \
  -H 'Content-Type: application/json' \
  -d '{"slug":"curl","method":"execute","params":{"url":"https://example.com"}}'
```

Specs:
- Framework: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/tool-adapter-framework.md`
- Batch 1: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/batch-1-tools.md`
- Batch 2: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/batch-2-tools.md`

## Persistent control plane state (Phase 14)

File-backed persistence for supervisor metadata across restarts:

```bash
# Configure state file path (optional, default: ./data/control-plane-state.json)
export STATE_STORE_PATH=/path/to/control-plane-state.json
```

Persists: idempotency store, request queue, circuit breaker state, peer registry metadata.

Recovery on startup:
1. Loads and prunes expired entries automatically
2. Coerces `HALF_OPEN` circuits to `OPEN` for safety
3. Restores peer metadata (tokenless) and triggers immediate heartbeat
4. Never auto-retries incomplete executions

Safety: atomic writes (temp + rename), debounced (1s), no tokens/secrets persisted.

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/persistent-state-spec.md`

## Cluster coordination (Phase 15)

Multi-supervisor clustering with leader election and shard-based routing:

```bash
# Enable cluster mode (requires federation enabled)
export SUPERVISOR_NODE_ID=node-1

# In supervisor options:
# { federation: { enabled: true }, cluster: { enabled: true, shardCount: 16 } }
```

Key behaviors:
- Leader: lexicographically smallest healthy nodeId
- Sharding: `hash(slug) % shardCount` with rendezvous hashing
- Owner executes locally; non-owners forward via federation remote client
- 5-second reconciliation tick: heartbeat \u2192 config validation \u2192 frozen snapshot
- Config mismatches (shardCount, timeouts) mark peers `DOWN`

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-spec.md`

## Partition containment (Phase 16)

Automatic partition detection and shard/leader freeze:
- Strict majority rule: `observedSize > previousStableSize / 2`
- While partitioned: no snapshot promotion, no rebalance, no remote forwarding
- Recovery requires restored membership stable for 2 consecutive ticks
- Convergence window (10s) prevents flap-driven rebalance

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-convergence-spec.md`

## Deployment topology (Phase 17)

Rolling upgrade and version compatibility safety:

```bash
# Bootstrap publishes node metadata automatically
# Version guard enforces: same MAJOR, MINOR skew <= 1
# Critical config (shardCount, timeouts) is restart-only
```

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/deployment-topology-spec.md`

## Cluster simulation (Phase 18)

Deterministic fault injection harness for multi-node testing:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"

# Validate simulator API
node -e "const { createClusterSimulator } = require('./simulation/cluster-simulator.js'); console.log(Object.keys(createClusterSimulator()));"
```

Covers: partitions, equal splits, rolling upgrades, rapid flapping, restart scenarios, mixed load.

Spec: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-simulation-spec.md`
