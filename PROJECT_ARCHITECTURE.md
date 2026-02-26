# AI Agent Bounty Hunt - Project Architecture

## Overview

The AI-Agent-BountyHunt project is a sophisticated local AI agent runtime stack that bridges GitHub Pro Agent Mode with OpenClaw for autonomous security research and bounty hunting workflows. It integrates multiple AI models, security tools (Burp Suite, LLDB), and a job queue system to enable intelligent, privileged task execution.

**Current Date**: February 22, 2026  
**Project Root**: `/Users/trevorrobey/AI-Agent-BountyHunt`  
**Primary Maintainer**: Trevor Robey

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER (AI Frontends)                  │
├─────────────────────────────────────────────────────────────────┤
│  • GitHub Pro Agent Mode (Claude 3.5 Sonnet / GPT-4o)           │
│  • Antigravity MCP Client                                       │
│  • VS Code / Codex MCP Client                                   │
│  • Qwen MCP Client                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                MCP BRIDGE LAYER (github-pro-mcp)                │
├─────────────────────────────────────────────────────────────────┤
│  • MCP Server (Model Context Protocol)                          │
│  • 15+ Tools for OpenClaw interaction                           │
│  • Director → Executor Pattern                                  │
│    - Director: GitHub Pro (reasoning/planning)                  │
│    - Executor: OpenClaw (privileged operations)                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              OPENCLAW BRIDGE SERVICE (Port 8787)                 │
├─────────────────────────────────────────────────────────────────┤
│  • Job Queue & State Management                                 │
│  • Async Task Execution                                         │
│  • Skill Tool Router                                            │
│  • Burp Suite Integration (BionicLink)                          │
│  • LLDB Crash Triage                                            │
│  • Bionic Ingest (HTTP Stability Analysis)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   EXECUTION LAYER (Skills)                      │
├─────────────────────────────────────────────────────────────────┤
│  • OpenClaw Agent (qwen2.5-coder:7b via Ollama)                │
│  • Runtime Skills (~/.openclaw/skills/)                         │
│  • OpenCode Daemon (Port 8091)                                  │
│  • Burp Suite Professional (via BionicLink extension)           │
│  • LLDB (via triage_bridge.py)                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. OpenClaw Bridge Service (`/openclaw-bridge/bridge/`)

**Location**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/bridge/server.ts`  
**Port**: 8787 (HTTP) or HTTPS with TLS  
**Purpose**: Central job queue and tool execution router

#### Key Features:
- **Job Management API**:
  - `POST /jobs` - Submit new async jobs
  - `GET /jobs` - List all jobs
  - `GET /jobs/:id` - Get job details
  - `POST /jobs/:id/cancel` - Cancel running job
  - `GET /health` - Health check endpoint

- **Tool Execution**:
  - `POST /execute-tool` - Execute skill tools or Burp operations
  - Routes to runtime skills in `~/.openclaw/skills/`
  - Enforces safety gates (mutation guards, scope locks)

- **Specialized Endpoints**:
  - `POST /lldb-stop` - Crash triage from LLDB
  - `POST /bionic-ingest` - HTTP stability analysis
  - `GET /mcp/sse` - MCP over SSE for Qwen compatibility

- **State Management**:
  - Workspace: `/Users/trevorrobey/Dev/Bounties`
  - Job artifacts stored in `${workspace}/jobs/<jobId>/`
  - Files: `MISSION_INPUT.json`, `MISSION_LOG.ndjson`, `MISSION_REPORT.md`

#### Security Controls:
- **Mutation Gates** (env vars):
  - `BOUNTY_HUNTER_ALLOW_MUTATIONS` - Bounty hunter skill mutations
  - `H1_ALLOW_MUTATIONS` - HackerOne report submission
  - `BURP_ALLOW_ACTIVE_SCAN` - Burp active scanning
  - `BURP_ALLOW_RAW_DATA` - Raw request/response access

- **Scope Lock**: All Burp operations validate against Burp Target Scope
- **Authentication**: Optional Bearer token via `BRIDGE_AUTH_TOKEN`
- **TLS**: Self-signed certs auto-generated at `~/.openclaw/tls/`

---

### 2. GitHub Pro MCP Bridge (`/openclaw-bridge/github-pro-mcp/`)

**Location**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/`  
**Purpose**: MCP server bridging GitHub Pro Agent Mode to OpenClaw

#### Architecture: Director → Executor Pattern

**Director (GitHub Pro)**:
- Uses Claude 3.5 Sonnet or GPT-4o from GitHub Pro subscription
- Handles reasoning, planning, code reading
- Decides when to delegate to OpenClaw

**Executor (OpenClaw)**:
- Local Ollama (`http://localhost:11434/v1`) with `qwen2.5-coder:7b`
- Executes privileged operations via bridge tools
- Runs async jobs and skill tools

#### MCP Tools (15 total):

**OpenClaw Direct (2)**:
- `openclaw_exec` - Send prompt to OpenClaw agent
- `openclaw_terminal` - Execute shell commands with full system access

**Job Queue (4)**:
- `job_submit` - Submit background job
- `job_list` - List all jobs
- `job_status` - Get job details by ID
- `job_cancel` - Cancel job

**ClawHub Skills (3)**:
- `skill_list` - List installed skills
- `skill_info` - Read skill manifest
- `execute_skill_tool` - Execute named skill function

**Burp Suite Integration (4)**:
- `burp_get_history` - Get proxy traffic (summarized)
- `burp_analyze_request` - Send through Repeater (scope-locked)
- `burp_active_scan` - Start active scan (gated)
- `burp_get_raw_request` - Get raw data (gated)

**Triage (2)**:
- `lldb_triage` - Submit LLDB crash event for async triage
- `bionic_ingest` - Submit HTTP pair for stability analysis

#### Client Configurations:

**VS Code / Codex**:
- Config: `/Users/trevorrobey/AI-Agent-BountyHunt/.vscode/mcp.json`
- Command: `node /.../github-pro-mcp/dist/server.js`

**Antigravity**:
- Config: `/Users/trevorrobey/AI-Agent-BountyHunt/AG for OC/mcp.json`
- Bootstrap: `antigravity-openclaw-bootstrap.sh`
- Auto-starts bridge services if unhealthy

**Qwen**:
- Config: `~/Library/Application Support/Qwen/settings.json`
- Bootstrap: `qwen-openclaw-bootstrap.sh`
- SSE endpoint: `http://127.0.0.1:8787/mcp/sse`

---

### 3. Runtime Skills (`/openclaw-bridge/skills/`)

**Source**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills/`  
**Runtime**: `~/.openclaw/skills/` (synced via `sync-skill-to-runtime.sh`)

#### Available Skills:

**1. opencode** (`skills/opencode/`)
- Purpose: OpenCode session management via daemon
- Tools: `opencode_session_create`, `opencode_session_message`, `opencode_session_state`, `opencode_session_close`
- Backend: OpenCode daemon at `http://127.0.0.1:8091`

**2. burp-suite** (`skills/burp-suite/`)
- Purpose: Safe Burp Suite integration via BionicLink
- Tools:
  - `burp_get_history` - Retrieve proxy traffic
  - `burp_analyze_request` - Repeater-style testing
  - `burp_active_scan` - Targeted active scanning (gated)
  - `burp_get_raw_request` - Raw session data (gated)
  - `burp_zero_click_triage` - Heuristic surface identification
- Backend: BionicLink extension in Burp at `http://127.0.0.1:8090`

**3. self-improving-agent** (`skills/self-improving-agent/`)
- Purpose: Continuous learning and error logging
- Features:
  - Log corrections, errors, feature requests
  - Promote learnings to project memory
  - Detect recurring patterns
  - Extract reusable skills
- Workspace files: `AGENTS.md`, `SOUL.md`, `TOOLS.md`, `MEMORY.md`
- Learning files: `.learnings/LEARNINGS.md`, `ERRORS.md`, `FEATURE_REQUESTS.md`

**4. find-skills** (`skills/find-skills/`)
- Purpose: Discover and install agent skills from skills.sh ecosystem
- Tools: Search via `npx skills find`, install via `npx skills add`
- Use when user asks "how do I do X" or "find a skill for X"

**5. tavily-search** (`skills/tavily-search/`)
- Purpose: AI-optimized web search via Tavily API
- Tools: `tavily_search`, `tavily_extract`
- Requires: `TAVILY_API_KEY` environment variable
- Options: deep search, news topic, date filtering

**6. algora-bountyfi** (`skills/algora-bountyfi/`)
- Purpose: Algora bounty management and submission
- (Details in skill manifest)

**7. nmap** (`skills/nmap/`)
- Purpose: Network scanning via Docker-wrapped nmap
- Tools: `nmap_run`, `nmap_health`, `nmap_read_output_chunk`, `nmap_search_output`, `nmap_output_meta`, `nmap_semantic_summary`, `nmap_anomaly_summary`, `nmap_anomaly_diff`, `nmap_tag_baseline`, `nmap_list_baselines`, `nmap_diff_against_baseline`
- Backend: Docker `kali-rolling` image with Linux `--net=host` auto-injection
- Generated by Skill Spawner (see below)

---

### 4. OpenCode Daemon (`/openclaw-bridge/github-pro-mcp/src/`)

**Port**: 8091  
**Backend**: `opencode serve` at port 8090  
**Purpose**: Local coding agent session management

#### API Endpoints:
- `GET /health` - Daemon health and metrics
- `POST /session` - Create session
- `POST /session/:id/message` - Send message to session
- `GET /session/:id/state` - Get session state
- `POST /session/:id/close` - Close session
- `GET /metrics` - Prometheus metrics

#### Configuration:
- `OPENCODE_MAX_ACTIVE_SESSIONS=2`
- `OPENCODE_QUEUE_MAX=8`
- Fallback to `opencode run --session` if serve unavailable

---

### 5. LLDB Integration (`/openclaw-bridge/lldb/`)

**File**: `triage_bridge.py`  
**Purpose**: Automatic crash triage from LLDB stop events

#### Workflow:
1. LLDB stop-hook triggers on crash signals/exceptions
2. Collects crash context:
   - Registers (PC, LR, SP, X0-X8 for ARM64)
   - Exception state (ESR, FAR, CPSR)
   - Disassembly window around PC
   - Memory inspection (X0 pointer deref)
   - Backtrace (30 frames max)
3. POSTs to `/lldb-stop` endpoint
4. Creates async job with `LLDB_STOP_EVENT.json`
5. OpenClaw agent generates `MISSION_REPORT.md` with:
   - Crash summary
   - Root cause hypotheses
   - Debugging recommendations
   - Mitigation suggestions

#### Safety:
- Defensive triage only
- No exploit/payload guidance
- Small payload cap (200 KiB)

---

### 7. Skill Spawner & Runtime Core

**Spawner**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/scripts/spawner.py`  
**Runtime Core**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/runtime/skill-runtime-core.js`  
**Templates**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/scripts/templates/`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/skill-runtime-v1.md`  
**Purpose**: Generate and scaffold new OpenClaw skills with a formalized runtime interface

#### Spawner CLI
```bash
python3 spawner.py <tool_name> [--flags "..."] [--gui] [--force] [--dry-run] [--no-restart-bridge]
```
- Generates `tools.js`, `_meta.json`, and `SKILL.md` from Jinja2 templates
- Two modes: `headless-kali` (CLI/Docker) and `gui-bridge` (BionicLink-style daemon)
- Auto-classifies GUI tools (`burpsuite`, `ghidra`, `wireshark`, `zap`, `maltego`)
- Platform-aware Docker networking: Linux auto-injects `--net=host` for `nmap`/`bettercap`
- Post-generation hooks: skill sync + PM2 bridge restart

#### TSP Runtime Layers (in generated skills)

| Layer | File | Purpose |
|-------|------|---------|
| Execution | `stdout.txt`, `stderr.txt`, `meta.json` | Secure spawn → redaction → lossless storage |
| Semantic | `semantic.json` | Error clustering, dedup, stack trace detection, entropy analysis |
| Anomaly | `anomalies.json` | Deterministic risk scoring (dominant errors, rare signatures, entropy isolation) |
| Baseline | `baselines.json` | Tool-scoped golden image tagging and on-demand diff |

#### Skill Runtime v1 Exports (per generated skill)

**Control**: `run()`, `health()`  
**Forensics**: `read_output_chunk()`, `search_output()`  
**Indexing**: `semantic_summary()`  
**Intelligence**: `anomaly_summary()`, `anomaly_diff()`  
**Baseline**: `tag_baseline()`, `list_baselines()`, `diff_against_baseline()`

---

### 8. MCP Skill Containers (Distributed Execution)

**MCP Server**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/runtime/mcp-skill-server.js`  
**Spawner v2**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/spawner/spawner-v2.js`  
**Dockerfile**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/containers/nmap/Dockerfile`  
**Specs**: `docs/mcp-skill-container-spec.md`, `docs/spawner-v2-spec.md`  
**Purpose**: Run individual skills as isolated Docker containers with JSON-RPC 2.0 MCP transport

#### Architecture
```
Bridge / Director Agent
        │
        ▼
  Spawner v2 (host-side)
  ├── initialize()         → Create Docker network, cleanup orphans
  ├── spawnSkill(slug)     → Build, run, health-probe container
  ├── terminateSkill(id)   → Graceful stop + remove
  ├── getSkillState(id)    → Registry lookup
  ├── listSkillStates()    → All active containers
  └── cleanupOrphans()     → Remove stale openclaw-skill-* containers
        │
        ▼
  MCP Skill Server (in-container, port 4000)
  ├── POST /mcp            → JSON-RPC 2.0 endpoint
  ├── Bearer auth           → MCP_SKILL_TOKEN
  ├── Method whitelist      → Skill Runtime v1 methods only
  └── Execution timeout     → 60s default
```

#### Container Security
- `--cap-drop ALL`, `--memory 512m`, `--cpus 1`, `--pids-limit 128`
- `--read-only`, `--security-opt no-new-privileges`
- Non-root user (`openclaw`)
- No host volume mounts, no Docker socket, no privileged mode
- Static image allowlist (no arbitrary images)
- Auto-generated per-container bearer tokens

#### Docker Network
- Network: `openclaw-net` (bridge driver)
- No host port publishing; containers communicate via internal IPs
- Health probing: direct IP probe with `docker exec` fallback (macOS compatibility)

---

### 9. Supervisor v1 (Routing & Pooling)

**Module**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/supervisor-v1-spec.md`  
**Purpose**: Deterministic routing and connection pooling layer over Spawner v2

#### Public API
- `initialize()` — Initialize Spawner v2 (no pre-spawning)
- `execute(slug, method, params)` — Route request to a pooled container instance
- `getStatus()` — Sanitized pool snapshot (no tokens exposed)
- `reapIdle()` — Terminate idle instances beyond TTL
- `shutdown()` — Gracefully terminate all instances

#### Routing Logic
1. Select oldest idle READY instance (deterministic: `lastUsedAt`, then `containerId`)
2. If none available, spawn new instance (if under `maxInstances`)
3. If at capacity, reject immediately (`SUPERVISOR_CAPACITY_EXCEEDED`)
4. Mark instance BUSY during execution, return to READY on completion
5. On transport failure: remove instance, terminate via Spawner, throw `INSTANCE_FAILED`

#### Per-Skill Configuration
- `maxInstances: 5` (default for nmap)
- `idleTTLms: 60000` (1 minute idle timeout)

#### Safety
- Never executes Docker commands directly (delegates to Spawner v2)
- Never exposes container tokens in status or errors
- Per-slug mutex prevents race conditions
- BUSY entries are never left stuck after timeout/failure

---

### 10. Observability (Telemetry)

**Module**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/observability/metrics.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/observability-spec.md`  
**Purpose**: Deterministic in-memory telemetry for Supervisor and Spawner

#### API
- `increment(counterName, labels?)` — Increment a counter
- `observe(histogramName, value, labels?)` — Record a histogram observation
- `gauge(name, value, labels?)` — Set a gauge value
- `snapshot()` — Deterministic sorted snapshot of all metrics
- `reset()` — Clear all metrics

#### Metric Namespaces

| Namespace | Owner | Examples |
|-----------|-------|----------|
| `supervisor.*` | Supervisor v1 | `supervisor.executions.total`, `supervisor.spawn.duration_ms`, `supervisor.instances.ready` |
| `spawner.*` | Spawner v2 | `spawner.spawn.attempt`, `spawner.spawn.duration_ms`, `spawner.health.timeout` |

#### Guarantees
- All metric operations are non-throwing
- Labels are canonicalized with sorted keys
- Histogram buckets: `[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf]`
- No tokens, auth headers, or sensitive data in metric labels

---

### 11. Security Baseline (Phase 9)

**Auth Guard**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/auth.js`  
**Rate Limiter**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/rate-limit.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/phase-9-security-baseline.md`  
**Purpose**: Authentication, rate limiting, and request tracing for the Supervisor ingress

#### Auth Guard (`createAuthGuard`)
- Config-driven enablement: `SUPERVISOR_AUTH_ENABLED`, `SUPERVISOR_AUTH_MODE`
- Bearer token validation with constant-time comparison (`crypto.timingSafeEqual`)
- Env-first token resolution (`SUPERVISOR_AUTH_TOKEN`) with constructor fallback
- Structured `UNAUTHORIZED` errors with `request_id` propagation

#### Rate Limiter (`createRateLimiter`)
- In-memory per-principal token bucket (O(1) check, no locks, no timers)
- Config: `SUPERVISOR_RATE_LIMIT_ENABLED`, `SUPERVISOR_RATE_LIMIT_RPS`, `SUPERVISOR_RATE_LIMIT_BURST`
- Bounded state: max 10,000 principals with overflow bucket
- Structured `SUPERVISOR_RATE_LIMIT_EXCEEDED` errors

#### Request ID Propagation
- Generated at `execute()` entry if not provided by caller
- Forwarded through: MCP JSON-RPC `id`, Spawner context, metrics labels, error responses
- Collision-resistant format, never contains token-derived material

#### STRIDE Threat Mapping
- Covers: Spoofing, Tampering, Repudiation, DoS, Elevation of Privilege
- Full acceptance checklist with measurable validation criteria

---

### 12. HTTP API Ingress (Phase 10)

**Server**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/http/server.js`  
**Handlers**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/http/handlers.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/http-api-spec.md`  
**Purpose**: External HTTP ingress wrapping Supervisor v1

#### Endpoints
- `POST /api/v1/execute` — Execute skill/tool with auth, rate limiting, retry policy
- `GET /health` — Service health with supervisor/queue status
- `GET /metrics` — In-memory metrics snapshot (JSON)
- `GET /metrics/prometheus` — Prometheus text format (when enabled)

#### Features
- Header forwarding: `Authorization`, `X-Request-Id`, `X-Principal-Id`
- Graceful shutdown on SIGINT/SIGTERM (drain timeout, then supervisor shutdown)
- HTTP-layer metrics: `http.requests.total`, `http.request.duration_ms`
- Optional: disabled by default (`httpServer.enabled = false`)

---

### 13. Production Hardening (Phase 11)

**TLS Config**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/tls-config.js`  
**Request Signing**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/request-signing.js`  
**Audit Logger**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/audit-logger.js`  
**Prometheus**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/monitoring/prometheus-exporter.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/phase-11-production-hardening.md`

#### TLS/mTLS
- TLS 1.2+ minimum, certificate chain validation on startup
- mTLS with client CA verification (`MTLS_ENABLED`, `MTLS_CA_PATH`)

#### Request Signing
- HMAC-SHA256 over canonical JSON payload
- `X-Signature` header validation on all JSON POST requests

#### Audit Logging
- Append-only structured NDJSON (execute, spawn, terminate, auth failures, circuit trips)
- Daily rotation with max size limit (100MB default)
- No token/secret values written

#### Prometheus Exporter
- `GET /metrics/prometheus` — text/plain 0.0.4 format
- Converts in-memory counters/histograms/gauges to Prometheus scrape format

---

### 14. Tool Adapter Framework (Phase 11A–11C)

**Framework**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/`  
**Specs**: `docs/tool-adapter-framework.md`, `docs/batch-1-tools.md`, `docs/batch-2-tools.md`  
**Purpose**: Direct CLI tool execution via standardized adapters, bypassing container lifecycle

#### Architecture
- `adapter-interface.js` — Contract: `execute()`, `validateInput()`, `normalizeOutput()`, `getResourceLimits()`
- `base-adapter.js` — Shared: timeout wrapping, validation flow, output size enforcement
- `tool-registry.js` — Allowlist-only registry with `seal()` for immutability
- `tool-validator.js` — Request validation before execution

#### Available Adapters

| Tool | Batch | Timeout | Max Output |
|------|-------|---------|------------|
| `curl` | 1 | 30s | 5MB |
| `nslookup` | 1 | 10s | 1MB |
| `whois` | 1 | 15s | 2MB |
| `hashcat` | 2 | 300s | 1MB |
| `sqlmap` | 2 | 300s | 5MB |
| `nikto` | 2 | 600s | 10MB |
| `aircrack` | 3 | 600s | 5MB |
| `msfvenom` | 3 | 60s | 10MB |
| `ffuf` | 3 | 600s | 10MB |

#### Security
- All tools use `spawn()` with argument arrays (`shell: false`)
- Input validation and whitelisting per adapter
- Hard timeout enforcement with process kill
- Reserved headers filtered (curl adapter)

#### Supervisor Routing
- Tool adapter requests bypass spawner/container/queue/circuit-breaker
- Auth and rate limiting still apply
- Tool metrics: `tool.executions.total`, `tool.execution.duration_ms`

---

### 15. Federation (Phase 12A–12B)

**Peer Registry**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/peer-registry.js`  
**Remote Client**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/remote-client.js`  
**Heartbeat**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/heartbeat.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/federation-spec.md`  
**Purpose**: Multi-node capacity-overflow delegation with deterministic peer selection

#### Architecture
- **Peer Registry** — `registerPeer()`, `removePeer()`, `listPeers()`, `getHealthyPeersForSlug()`
- **Remote Client** — `executeRemote(peer, payload)` via `POST /api/v1/execute` on remote nodes
- **Heartbeat** — Periodic `GET /health` probes, updates peer UP/DOWN status and latency

#### Deterministic Routing (Phase 12B)
1. Federation triggers only when local capacity is exhausted and peers support the slug
2. Peers selected by latency then peerId (deterministic, no randomization)
3. 429/503 responses trigger failover to next healthy peer
4. Transport timeout marks peer DOWN; stops failover without idempotency key
5. Remote success returns immediately, skips local execution

#### Metrics
- `supervisor.federation.attempt`, `success`, `failure`, `latency_ms`, `peer_down`
- Remote path does not increment local execution/spawn/instance metrics

---

### 16. Persistent Control Plane State (Phase 14)

**Persistent Store**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/state/persistent-store.js`  
**State Manager**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/state/state-manager.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/persistent-state-spec.md`  
**Purpose**: File-backed persistence for supervisor control plane metadata across process restarts

#### Persisted Structures
- Idempotency store (replay entries with TTL)
- Request queue (pending retry entries)
- Circuit breaker state (per-slug open/closed/half-open)
- Peer registry metadata (no tokens ever persisted)

#### Guarantees
- Atomic writes via temp file + `rename`
- Debounced (max once per second)
- Graceful corruption handling (load failure is non-fatal)
- Sensitive data exclusions enforced (no tokens, secrets, TLS keys)

#### Recovery on Startup
1. Load persisted envelope, prune expired idempotency/queue entries
2. Coerce `HALF_OPEN` circuit states to `OPEN`
3. Restore peer metadata (tokenless), trigger immediate heartbeat
4. No auto-retry of incomplete executions

#### Configuration
- `STATE_STORE_PATH` env var (default: `./data/control-plane-state.json`)

---

### 17. Cluster Coordination (Phase 15)

**Leader Election**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/leader-election.js`  
**Cluster Manager**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/cluster-manager.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-spec.md`  
**Purpose**: Deterministic multi-supervisor coordination with shard-based routing

#### Leader Election
- Lexicographically smallest healthy `nodeId` becomes leader
- API: `isLeader()`, `getCurrentLeader()`, `onLeadershipChange(callback)`

#### Shard Ownership
- `shardId = hash(slug) % shardCount` (default 16 shards)
- Rendezvous hashing over healthy, slug-capable nodes
- Only shard owner executes locally; non-owners forward via federation

#### Reconciliation
- 5-second tick: heartbeat → peer config validation → immutable membership snapshot
- Routing/election decisions use only the frozen snapshot (no request-time registry reads)
- Config mismatches mark peer `DOWN` and increment `cluster.config_mismatch`

#### Failover
- Timed-out owner marked `DOWN`; retry allowed with `idempotencyKey`
- Without idempotency key: cross-peer retry blocked (duplicate execution prevention)

#### Metrics
- `cluster.leader_elected`, `cluster.shard_rebalance`, `cluster.node_status`, `cluster.config_mismatch`

---

### 18. Partition Containment & Convergence (Phase 16)

**Partition Detector**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/partition-detector.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-convergence-spec.md`  
**Purpose**: Detect network partitions and freeze shard/leader state to prevent split-brain

#### Partition Rules
- Strict majority: `observedSize > previousStableSize / 2`
- Equal-split containment (e.g., 6→3: both sides freeze)
- Baseline derived from last promoted stable snapshot only

#### While Partitioned
- No stable snapshot promotion or shard rebalance
- Remote forwarding disabled (backpressure)
- Leader transitions suppressed, pinned to stable state

#### Recovery
- Observed size ≥ `ceil(baseline / 2)` for 2 consecutive ticks
- Convergence window (10s default) prevents flap-driven rebalance

#### Metrics
- `cluster.partition_detected`, `cluster.partition_recovered`, `cluster.partition_state`

---

### 19. Deployment Topology & Rolling Upgrades (Phase 17)

**Bootstrap Manager**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/deployment/bootstrap-manager.js`  
**Version Guard**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/deployment/version-guard.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/deployment-topology-spec.md`

#### Bootstrap Validation
- Enforces: federation enabled, explicit nodeId, required cluster params, TLS when HTTP enabled
- Publishes node metadata: `nodeId`, `softwareVersion`, `configHash`, `shardCount`

#### Version Compatibility
- Same MAJOR required, MINOR skew ≤ 1
- Incompatible peers marked `DOWN`, `cluster.version_mismatch` incremented
- Version-skew freeze: no promotion/rebalance/leader transition while `compatiblePopulation ≤ observedPopulation / 2`

#### Config Safety
- Critical params (`shardCount`, `leaderTimeoutMs`, `heartbeatIntervalMs`) are restart-only

---

### 20. Cluster Simulation & Fault Injection (Phase 18)

**Simulator**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/simulation/cluster-simulator.js`  
**Fault Injector**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/simulation/fault-injector.js`  
**Spec**: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/cluster-simulation-spec.md`  
**Purpose**: Deterministic in-process harness for multi-node cluster scenario testing

#### Capabilities
- Deterministic clock (no wall-clock leakage)
- Real production Supervisor + ClusterManager APIs (no mocked control plane)
- Fault injection: node down, latency, timeout, partition (symmetric & asymmetric), config/version skew

#### Scenario Coverage
- 5-node partition, 6-node equal split, rolling upgrades, rapid flapping
- Queue pressure + federation routing, mixed tool/skill load
- Restart during partition, freeze probe, and rolling upgrade

#### Validation Report
- `no_split_brain_under_partition`, `no_duplicate_execution_detected`, `freeze_behavior_correct`
- `rolling_upgrade_invariants_hold`, `snapshot_consistency_preserved`, `no_deadlock_detected`

---

### 21. Burp Suite Integration (BionicLink)

**Extension**: BionicLink (custom Burp extension)  
**Port**: 8090 (HTTP)  
**Bridge Integration**: Via `/execute-tool` endpoints

#### Features:
- **Scope Lock**: All operations validate against Burp Target Scope
- **Traffic Summarization Protocol (TSP)**: Reduces token usage
- **Redaction**: Sensitive headers automatically redacted
- **Safety Gates**: Active scan and raw data require explicit enablement

#### Endpoints (via bridge):
- `/history` - Get proxy traffic
- `/scope` - Check URL scope
- `/repeater` - Send custom request
- `/scan` - Start active scan
- `/raw` - Get raw request/response (gated)

---

## Deployment & Operations

### Process Management

**Recommended**: PM2 (Process Manager 2)
- Apps: `openclaw-bridge`, `openclaw-mcp`, `openclaw-opencode-daemon`
- Auto-restart on failure
- Log rotation via `pm2-logrotate`
- State persistence via `pm2 save`

**Alternative**: macOS LaunchAgents
- Generated by `mcp-install-launchd.sh`
- Files in `~/Library/LaunchAgents/`
- **Warning**: Don't mix PM2 and LaunchAgents

### Startup Flow

1. **Environment Setup**:
   - Load `.env` from `/openclaw-bridge/.env`
   - Key vars: `BRIDGE_PORT`, `OPENCLAW_GATEWAY_BASE_URL`, `OPENCLAW_DEFAULT_MODEL`

2. **Skill Sync**:
   - Run `sync-skill-to-runtime.sh`
   - Copies skills from repo to `~/.openclaw/skills/`

3. **Service Start**:
   - `mcp-start-pm2.sh` starts all services
   - Bridge on port 8787
   - OpenCode daemon on port 8091
   - MCP server (stdio or SSE)

4. **Health Checks**:
   ```bash
   curl http://127.0.0.1:8787/health
   curl http://127.0.0.1:8091/health
   curl http://localhost:11434/v1/models
   ```

### Client Wiring

**VS Code**:
- MCP config at `.vscode/mcp.json`
- Points to `github-pro-mcp/dist/server.js`

**Antigravity**:
- Runtime bundle at `AG for OC/`
- Bootstrap script auto-starts services
- MCP config installed to `~/Library/Application Support/Antigravity/User/mcp.json`

**Qwen**:
- SSE endpoint at `http://127.0.0.1:8787/mcp/sse`
- Config in Qwen settings directory

---

## Data Flow Examples

### Example 1: Bounty Research Task

```
User (GitHub Pro) → "Analyze this repo for security issues"
    ↓
GitHub Pro Agent (Director)
    - Reads code, identifies suspicious patterns
    - Decides to delegate deep analysis
    ↓
openclaw_exec tool
    ↓
OpenClaw Bridge (Port 8787)
    - Creates job with instruction + repo URL
    - Writes MISSION_INPUT.json
    ↓
Job Worker
    - Clones repo to job workspace
    - Invokes OpenClaw agent (qwen2.5-coder:7b)
    ↓
OpenClaw Agent
    - Analyzes code
    - Uses burp_get_history if web app
    - Generates MISSION_REPORT.md
    ↓
User receives report with findings and recommendations
```

### Example 2: LLDB Crash Triage

```
LLDB stops on SIGSEGV
    ↓
triage_bridge.py stop-hook
    - Collects registers, backtrace, disassembly
    - POSTs to /lldb-stop
    ↓
OpenClaw Bridge
    - Creates job with LLDB_STOP_EVENT.json
    - Sets triage-specific hints
    ↓
Job Worker
    - Invokes OpenClaw agent
    - Provides crash context
    ↓
OpenClaw Agent
    - Analyzes crash pattern
    - Generates hypotheses
    - Recommends debugging steps
    ↓
MISSION_REPORT.md with:
    - Crash summary
    - Likely root causes
    - Next steps for debugging
    - Mitigation suggestions
```

### Example 3: Burp Active Scan

```
User → "Scan this endpoint for vulnerabilities"
    ↓
GitHub Pro Agent
    - Validates target is in scope
    - Checks BURP_ALLOW_ACTIVE_SCAN=true
    ↓
burp_active_scan tool
    ↓
OpenClaw Bridge
    - Validates URL against Burp scope
    - Forwards to BionicLink /scan
    ↓
Burp Suite (via BionicLink)
    - Runs active scan
    - Returns scan results
    ↓
Bridge summarizes results (TSP)
    ↓
User receives scan summary with findings
```

---

## Security Architecture

### Defense in Depth

**1. Network Isolation**:
- All services bound to `127.0.0.1` (loopback only)
- No external network exposure by default

**2. Authentication**:
- Optional Bearer token (`BRIDGE_AUTH_TOKEN`)
- Applied to all bridge endpoints if configured

**3. Authorization Gates**:
- Mutation operations require explicit env var enablement
- Default: all mutations disabled
- Burp active scan requires `BURP_ALLOW_ACTIVE_SCAN=true`
- HackerOne submission requires `H1_ALLOW_MUTATIONS=true`

**4. Scope Enforcement**:
- Burp operations validate against Target Scope
- Out-of-scope requests rejected with 403

**5. Data Redaction**:
- Sensitive headers automatically redacted:
  - `Authorization`, `Cookie`, `Set-Cookie`
  - `X-API-Key`, `X-Auth-Token`
- Raw request access gated behind `BURP_ALLOW_RAW_DATA`

**6. Payload Limits**:
- LLDB events capped at 200 KiB
- Bionic ingest events capped at 200 KiB
- Prevents log flooding and DoS

**7. Safety Prompts**:
- LLDB triage: "Do not provide exploit guidance"
- Bionic ingest: "Do NOT generate weaponized payloads"
- Generic tasks: "Do not provide exploit or bypass guidance"

---

## Development Workflow

### Directory Structure

```
/Users/trevorrobey/AI-Agent-BountyHunt/
├── openclaw-bridge/               # Main bridge service
│   ├── bridge/                    # Bridge server (TypeScript)
│   │   └── server.ts              # Main HTTP server
│   ├── runtime/                   # Skill Runtime Core
│   │   ├── skill-runtime-core.js  # Extracted runtime module (TSP v2/v3)
│   │   └── mcp-skill-server.js    # JSON-RPC MCP server for containers
│   ├── spawner/                   # Container lifecycle management
│   │   └── spawner-v2.js          # Spawner v2 control plane
│   ├── supervisor/                # Routing and pooling layer
│   │   └── supervisor-v1.js       # Supervisor v1 (routing, pooling, lifecycle)
│   ├── observability/              # Telemetry system
│   │   └── metrics.js             # In-memory metrics (counters, histograms, gauges)
│   ├── security/                  # Security controls
│   │   ├── auth.js                # Auth guard (constant-time bearer validation)
│   │   ├── rate-limit.js          # Per-caller token bucket rate limiter
│   │   ├── tls-config.js          # TLS/mTLS configuration
│   │   ├── request-signing.js     # HMAC-SHA256 request signature verification
│   │   └── audit-logger.js        # Structured append-only audit logging
│   ├── http/                      # HTTP API ingress (Phase 10)
│   │   ├── server.js              # HTTP server with graceful shutdown
│   │   └── handlers.js            # Route handlers (/api/v1/execute, /health, /metrics)
│   ├── monitoring/                # Production monitoring
│   │   └── prometheus-exporter.js # Prometheus text format exporter
│   ├── tools/                     # Tool Adapter Framework (Phase 11A–11C)
│   │   ├── adapter-interface.js   # Adapter contract definition
│   │   ├── base-adapter.js        # Shared adapter base class
│   │   ├── tool-registry.js       # Allowlist tool registry
│   │   ├── tool-validator.js      # Request validation layer
│   │   └── adapters/              # Individual tool adapters
│   │       ├── index.js           # Batch 1 registration
│   │       ├── batch-2-index.js   # Batch 2 registration
│   │       ├── curl-adapter.js    # HTTP client adapter
│   │       ├── nslookup-adapter.js # DNS lookup adapter
│   │       ├── whois-adapter.js   # WHOIS query adapter
│   │       ├── hashcat-adapter.js # Password cracking adapter
│   │       ├── sqlmap-adapter.js  # SQL injection testing adapter
│   │       ├── nikto-adapter.js   # Web server scanner adapter
│   │       ├── batch-3-index.js   # Batch 3 registration
│   │       ├── aircrack-adapter.js # Wireless cracking adapter
│   │       ├── msfvenom-adapter.js # Payload generation adapter
│   │       └── ffuf-adapter.js    # Web fuzzer adapter
│   ├── federation/                # Multi-node federation (Phase 12)
│   │   ├── peer-registry.js       # Peer registry and health tracking
│   │   ├── remote-client.js       # Remote execution client
│   │   └── heartbeat.js           # Periodic peer health probing
│   ├── state/                     # Persistent control plane state (Phase 14)
│   │   ├── persistent-store.js    # Atomic file-backed JSON persistence
│   │   └── state-manager.js       # State recovery orchestration
│   ├── cluster/                   # Multi-supervisor coordination (Phase 15–16)
│   │   ├── leader-election.js     # Deterministic leader election
│   │   ├── cluster-manager.js     # Shard ownership, reconciliation, heartbeat
│   │   └── partition-detector.js   # Network partition detection and containment
│   ├── deployment/                # Deployment topology (Phase 17)
│   │   ├── bootstrap-manager.js   # Node startup validation and metadata
│   │   └── version-guard.js       # Version compatibility guard
│   ├── simulation/                # Cluster simulation (Phase 18)
│   │   ├── cluster-simulator.js   # Deterministic multi-node simulator
│   │   └── fault-injector.js      # Fault injection interface
│   ├── containers/                # Dockerfiles for containerized skills
│   │   └── nmap/Dockerfile        # Containerized nmap skill
│   ├── github-pro-mcp/            # MCP bridge for GitHub Pro
│   │   ├── src/                   # MCP server source
│   │   │   ├── server.ts          # MCP server entry
│   │   │   ├── tools/             # Tool implementations
│   │   │   │   ├── openclaw.ts    # OpenClaw direct tools
│   │   │   │   ├── jobs.ts        # Job queue tools
│   │   │   │   ├── burp.ts        # Burp integration tools
│   │   │   │   ├── skills.ts      # Skill lookup tools
│   │   │   │   └── triage.ts      # Triage tools
│   │   │   └── safety.ts          # Safety prompt templates
│   │   └── scripts/               # Client bootstrap scripts
│   ├── skills/                    # Skill source-of-truth
│   │   ├── nmap/                  # Generated nmap skill (Spawner reference)
│   │   ├── opencode/              # OpenCode session skill
│   │   ├── burp-suite/            # Burp integration skill
│   │   ├── self-improving-agent/  # Learning/logging skill
│   │   ├── find-skills/           # Skill discovery skill
│   │   ├── tavily-search/         # Web search skill
│   │   └── algora-bountyfi/       # Bounty management skill
│   ├── scripts/                   # Operational + generation scripts
│   │   ├── spawner.py             # Master Skill Spawner
│   │   ├── templates/             # Jinja2 templates for skill generation
│   │   │   ├── kali_cli_tools.js.j2
│   │   │   ├── gui_bridge_tools.js.j2
│   │   │   ├── skill_manifest.json.j2
│   │   │   └── skill_readme.md.j2
│   │   ├── bridge-control.sh      # Bridge start/stop/status
│   │   ├── submit-task.sh         # CLI job submission
│   │   ├── sync-skill-to-runtime.sh  # Skill sync
│   │   └── generate-tls-certs.sh  # TLS cert generation
│   ├── lldb/                      # LLDB integration
│   │   └── triage_bridge.py       # LLDB stop-hook
│   ├── docs/                      # Documentation
│   │   ├── skill-runtime-v1.md    # Skill Runtime v1 interface spec
│   │   ├── mcp-skill-container-spec.md  # MCP container boundary spec
│   │   ├── spawner-v2-spec.md     # Spawner v2 lifecycle spec
│   │   ├── supervisor-v1-spec.md  # Supervisor v1 routing/pooling spec
│   │   ├── observability-spec.md  # Observability telemetry spec
│   │   ├── phase-9-security-baseline.md  # Security baseline and acceptance checklist
│   │   ├── http-api-spec.md       # HTTP API ingress spec (Phase 10)
│   │   ├── phase-11-production-hardening.md  # TLS, signing, audit, Prometheus
│   │   ├── tool-adapter-framework.md  # Tool adapter framework spec
│   │   ├── batch-1-tools.md       # Batch 1 tool adapters (curl, nslookup, whois)
│   │   ├── batch-2-tools.md       # Batch 2 tool adapters (hashcat, sqlmap, nikto)
│   │   ├── batch-3-tools.md       # Batch 3 tool adapters (aircrack, msfvenom, ffuf)
│   │   ├── federation-spec.md     # Federation transport and routing spec
│   │   ├── persistent-state-spec.md  # Persistent control plane state spec
│   │   ├── cluster-spec.md        # Cluster coordination and leader election spec
│   │   ├── cluster-convergence-spec.md  # Partition containment and convergence
│   │   ├── deployment-topology-spec.md  # Rolling upgrades and version safety
│   │   ├── cluster-simulation-spec.md   # Multi-node simulation harness
│   │   ├── API.md                 # API contract
│   │   ├── BURP_INTEGRATION.md    # Burp setup guide
│   │   ├── LLDB_TRIAGE.md         # LLDB setup guide
│   │   └── OPERATIONS.md          # Operations guide
│   ├── tests/                     # Test suite
│   ├── .env                       # Environment config (private)
│   ├── .env.example               # Env template
│   ├── package.json               # Bridge dependencies
│   └── tsconfig.json              # TypeScript config
├── AG for OC/                     # Antigravity runtime bundle
│   ├── mcp.json                   # Antigravity MCP config
│   ├── README.md                  # Setup instructions
│   └── install-to-antigravity.sh  # Install script
├── .vscode/                       # VS Code config
│   └── mcp.json                   # VS Code MCP config
└── PROJECT_ARCHITECTURE.md        # This document
```

### Build Process

```bash
# Install dependencies
cd /Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge
npm install
npm --prefix github-pro-mcp install

# Build TypeScript
npm run bridge:build          # Builds bridge/server.ts
npm --prefix github-pro-mcp run build  # Builds MCP server

# Start services
cd github-pro-mcp
./scripts/mcp-start-pm2.sh    # Starts all services via PM2
```

### Testing

```bash
# Run bridge tests
npm run bridge:test

# Manual health check
curl http://127.0.0.1:8787/health | jq

# Submit test job
./scripts/submit-task.sh \
  --instruction "Test job submission" \
  --requester "test"
```

---

## Configuration Reference

### Environment Variables (`.env`)

```bash
# Bridge Service
BRIDGE_PORT=8787
BRIDGE_WORKSPACE_ROOT=/Users/trevorrobey/Dev/Bounties
BRIDGE_HTTP=true              # Use HTTP instead of HTTPS
BRIDGE_AUTH_TOKEN=            # Optional auth token

# OpenClaw Gateway
OPENCLAW_TRANSPORT=cli        # cli or http
OPENCLAW_GATEWAY_BASE_URL=http://localhost:11434/v1
OPENCLAW_DEFAULT_MODEL=qwen2.5-coder:7b
OPENCLAW_TIMEOUT_MS=180000

# Burp Suite (BionicLink)
BIONICLINK_BASE_URL=http://127.0.0.1:8090
BIONICLINK_TIMEOUT_MS=8000
BURP_ALLOW_ACTIVE_SCAN=false
BURP_ALLOW_RAW_DATA=false

# OpenCode Daemon
OPENCODE_SERVER_BASE_URL=http://127.0.0.1:8090
OPENCODE_DAEMON_BASE_URL=http://127.0.0.1:8091
OPENCODE_MAX_ACTIVE_SESSIONS=2
OPENCODE_QUEUE_MAX=8

# Mutation Gates
BOUNTY_HUNTER_ALLOW_MUTATIONS=false
H1_ALLOW_MUTATIONS=false
```

- **Python** (3.9+) with Jinja2 (`pip install jinja2`)
- **Docker** (`brew install --cask docker`) — for Kali skill execution
- **Node.js** (v18+) with npm
- **PM2** (`npm install -g pm2`)
- **Ollama** (`brew install ollama`)
- **OpenCode CLI** (`brew install anomalyco/tap/opencode`)
- **Burp Suite Professional** (with BionicLink extension)
- **LLDB** (Xcode Command Line Tools)

### Models

**Local (Ollama)**:
- `qwen2.5-coder:7b` (default) - 7B parameter coding model

**Cloud (via gateway)**:
- `openclaw-sonnet-4` - Claude 3.5 Sonnet
- `openclaw-gpt-4o` - GPT-4o

---

## Use Cases

### 1. Security Research & Bug Bounty

- **Code Analysis**: Clone repos, analyze for vulnerabilities
- **Web App Testing**: Use Burp integration for endpoint discovery
- **Automated Scanning**: Run targeted active scans on suspicious endpoints
- **Report Generation**: Auto-generate vulnerability reports

### 2. Crash Triage & Debugging

- **LLDB Integration**: Automatic crash analysis
- **Root Cause Hypotheses**: AI-generated debugging guidance
- **Mitigation Suggestions**: Fix recommendations

### 3. Protocol Stability Analysis

- **HTTP Fuzzing Prep**: Identify integer width, format string issues
- **Serialization Analysis**: Detect risky serialization patterns
- **Input Validation**: Suggest validation improvements

### 4. Continuous Learning

- **Error Logging**: Track failures and corrections
- **Knowledge Base**: Build project-specific memory
- **Skill Extraction**: Convert learnings into reusable skills

### 5. Multi-Agent Collaboration

- **Director/Executor**: GitHub Pro plans, OpenClaw executes
- **Session Communication**: Share context between agents
- **Background Jobs**: Async processing for long tasks

---

## Troubleshooting

### Bridge Not Starting

```bash
# Check logs
pm2 logs openclaw-bridge --lines 120

# Verify port availability
lsof -i :8787

# Check environment
cat /Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/.env
```

### Skills Not Loading

```bash
# Sync skills to runtime
./scripts/sync-skill-to-runtime.sh

# Verify runtime path
ls ~/.openclaw/skills/

# Restart services
pm2 restart openclaw-bridge
```

### Burp Integration Failing

```bash
# Check BionicLink is running in Burp
curl http://127.0.0.1:8090/health

# Verify scope is set in Burp
# Check BURP_ALLOW_ACTIVE_SCAN if scanning

# Check bridge logs
pm2 logs openclaw-bridge --lines 50
```

### LLDB Triage Not Working

```bash
# Verify triage_bridge.py is loaded
lldb
(lldb) target stop-hook list

# Check bridge health
curl http://127.0.0.1:8787/health

# Check fallback logs
ls ~/.openclaw/logs/lldb-triage/
```

---

## Future Enhancements

### Planned Features

1. **Enhanced Skill Discovery**:
   - Auto-suggest skills based on user queries
   - Skill recommendation engine

2. **Multi-Model Orchestration**:
   - Dynamic model selection based on task complexity
   - Cost/performance optimization

3. **Advanced Security Controls**:
   - Fine-grained permission system
   - Audit logging for all operations
   - Rate limiting and quotas

4. **Improved Error Recovery**:
   - Automatic retry with backoff
   - Fallback strategies for failed tools
   - Better error messages for users

5. **Performance Monitoring**:
   - Real-time metrics dashboard
   - Job performance analytics
   - Resource usage tracking

---

## Conclusion

The AI-Agent-BountyHunt project represents a sophisticated integration of AI agents, security tools, and job orchestration. By combining GitHub Pro's reasoning capabilities with OpenClaw's execution power, it enables autonomous security research while maintaining strict safety controls.

Key strengths:
- **Modular Architecture**: Clear separation of concerns
- **Safety First**: Multiple layers of security controls
- **Extensible**: Skill-based system for adding capabilities
- **Production Ready**: PM2 management, health checks, logging

This architecture is designed for security researchers, bug bounty hunters, and developers who need intelligent automation with privileged access, all while maintaining defensive security practices.

---

**Document Version**: 1.9  
**Last Updated**: February 25, 2026  
**Maintained By**: Trevor Robey
