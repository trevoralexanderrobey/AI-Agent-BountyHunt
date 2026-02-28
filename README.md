# AI-Agent-BountyHunt

Local AI agent runtime environment for autonomous security research and bug bounty hunting.

## Overview

This repository contains local environments, integrations, and bridges for running various MCP (Model Context Protocol) servers and AI agent runtimes for bug hunting against targets like Burp Suite, local source code, and local LLMs.

Key capabilities:
- **OpenClaw Bridge** — Job queue, tool router, and Burp/LLDB integrations on port `8787`
- **Skill Spawner** — Generate new tool skills from Kali tool names with `spawner.py`
- **Skill Runtime v1** — Extracted runtime core with TSP v2/v3 (lossless storage, semantic analysis, anomaly detection, cross-job diff, baseline tagging)
- **MCP Skill Containers** — Isolated Docker containers with JSON-RPC 2.0 transport
- **Supervisor v1** — Deterministic routing, connection pooling, and lifecycle management for skill containers
- **Observability** — In-memory telemetry (counters, histograms, gauges) for Supervisor and Spawner
- **Security Baseline** — Auth guard (constant-time bearer), per-caller rate limiting, `request_id` propagation
- **HTTP API** — External ingress layer (`POST /api/v1/execute`, `/health`, `/metrics`) with graceful shutdown
- **Production Hardening** — TLS/mTLS, HMAC request signing, audit logging, Prometheus exporter
- **Tool Adapter Framework** — Direct CLI tool execution (curl, nslookup, whois, hashcat, sqlmap, nikto, aircrack, msfvenom, ffuf)
- **Federation** — Multi-node peer registry, remote execution, heartbeat monitoring, deterministic overflow routing
- **Persistent State** — File-backed control plane persistence (idempotency, queue, circuit breaker, peer metadata)
- **Cluster Coordination** — Leader election, shard ownership, rendezvous hashing, multi-supervisor routing
- **Partition Containment** — Majority-loss detection, convergence stabilization, shard/leader freeze
- **Deployment Topology** — Rolling upgrade safety, version compatibility guard, bootstrap validation
- **Operational Runbooks** — Preflight validation, SLO/SLI tracking, scaling strategy, and disaster recovery playbooks
- **Execution Plane Hardening** — Container runtime integration scaffolding, resource/egress/sandbox policies
- **Controlled Runtime Activation** — Opt-in containerized execution enforcing sandbox and image provenance guardrails
- **Execution Governance & Resource Control** — Safe secret injection, threat models, and deterministic execution quotas
- **Execution Policy Authority** — Cryptographically signed JSON manifests enforcing environment configuration limits
- **Cluster Simulation** — Deterministic fault injection harness for multi-node scenario testing
- **MCP Bridge** — Director → Executor pattern connecting GitHub Pro / Antigravity / Codex to OpenClaw

### OpenClaw Bridge Runtime

Located in `openclaw-bridge/`. 

This repo runs the OpenClaw bridge, GitHub Pro MCP server, and OpenCode daemon against a local Ollama instance (default model `qwen2.5-coder:7b`).

- **Bridge API:** `http://127.0.0.1:8787`
- **OpenCode Daemon:** `http://127.0.0.1:8091`

#### Quick Start (Bridge)
```bash
cd "openclaw-bridge"
npm install
npm run bridge:build

npm --prefix github-pro-mcp install
npm --prefix github-pro-mcp run build

# Start full stack (bridge + MCP + OpenCode daemon) via PM2
cd github-pro-mcp
./scripts/mcp-start-pm2.sh
```

#### Skill Spawner (Generate New Skills)
```bash
# Generate a CLI skill for any Kali tool
python3 openclaw-bridge/scripts/spawner.py nmap --flags "-sV -sC"
python3 openclaw-bridge/scripts/spawner.py nikto --force

# Preview without writing files
python3 openclaw-bridge/scripts/spawner.py dirb --dry-run
```

Generated skills include the full TSP v2/v3 runtime: lossless output storage, semantic clustering, anomaly extraction, cross-job diff, and baseline tagging. See the [Skill Runtime v1 Spec](./openclaw-bridge/docs/skill-runtime-v1.md) for the complete interface contract.

#### MCP Skill Containers (Distributed Execution)
```bash
# Build a containerized nmap skill
cd openclaw-bridge
docker build -f containers/nmap/Dockerfile -t openclaw-nmap-skill .

# Run with hardened security
docker run -d -p 4000:4000 --cap-drop ALL --name nmap-skill \
  -e MCP_SKILL_TOKEN=your_token -e TOOL_NAME=nmap -e SKILL_SLUG=nmap \
  openclaw-nmap-skill

# Spawn via Spawner v2 (automated lifecycle)
node -e "(async()=>{const {createSpawnerV2}=require('./spawner/spawner-v2.js');const s=createSpawnerV2();await s.initialize();console.log(await s.spawnSkill('nmap'))})().catch(console.error)"
```

#### Health Checks
```bash
curl -sS http://127.0.0.1:8787/health | jq
curl -sS http://127.0.0.1:8091/health | jq
curl -sS http://localhost:11434/v1/models | jq
```

### AG Runtime For OpenClaw

Located in `AG for OC/`. 

This directory is the generated runtime bundle for Antigravity's OpenClaw MCP client. It copies the `mcp.json` into the Antigravity User config space.

#### Install / Update Configure
```bash
cd "AG for OC"
./install-to-antigravity.sh
```

## Client Wiring

- **Codex / VS Code:** `.vscode/mcp.json`
- **Antigravity Installed MCP:** `/Users/trevorrobey/Library/Application Support/Antigravity/User/mcp.json`
- **Qwen Bootstrap Script:** `openclaw-bridge/github-pro-mcp/scripts/qwen-openclaw-bootstrap.sh`
- **Antigravity Bootstrap Script:** `openclaw-bridge/github-pro-mcp/scripts/antigravity-openclaw-bootstrap.sh`

## Documentation

- [Project Architecture](./PROJECT_ARCHITECTURE.md)
- [Skill Runtime v1 Spec](./openclaw-bridge/docs/skill-runtime-v1.md) — Formal interface contract for generated skills
- [MCP Skill Container Spec](./openclaw-bridge/docs/mcp-skill-container-spec.md) — JSON-RPC container transport boundary
- [Spawner v2 Spec](./openclaw-bridge/docs/spawner-v2-spec.md) — Container lifecycle control plane
- [Supervisor v1 Spec](./openclaw-bridge/docs/supervisor-v1-spec.md) — Routing, pooling, and lifecycle management
- [Observability Spec](./openclaw-bridge/docs/observability-spec.md) — In-memory telemetry system
- [Phase 9 Security Baseline](./openclaw-bridge/docs/phase-9-security-baseline.md) — Auth, rate limiting, request tracing, threat model
- [HTTP API Spec](./openclaw-bridge/docs/http-api-spec.md) — Phase 10 external HTTP ingress
- [Phase 11 Production Hardening](./openclaw-bridge/docs/phase-11-production-hardening.md) — TLS, signing, audit, Prometheus
- [Tool Adapter Framework](./openclaw-bridge/docs/tool-adapter-framework.md) — Phase 11A adapter pattern
- [Batch 1 Tools](./openclaw-bridge/docs/batch-1-tools.md) — curl, nslookup, whois adapters
- [Batch 2 Tools](./openclaw-bridge/docs/batch-2-tools.md) — hashcat, sqlmap, nikto adapters
- [Batch 3 Tools](./openclaw-bridge/docs/batch-3-tools.md) — aircrack, msfvenom, ffuf adapters
- [Federation Spec](./openclaw-bridge/docs/federation-spec.md) — Multi-node peer registry and deterministic routing
- [Persistent State Spec](./openclaw-bridge/docs/persistent-state-spec.md) — File-backed control plane persistence
- [Cluster Spec](./openclaw-bridge/docs/cluster-spec.md) — Leader election and shard-based multi-supervisor routing
- [Cluster Convergence Spec](./openclaw-bridge/docs/cluster-convergence-spec.md) — Partition containment and convergence
- [Deployment Topology Spec](./openclaw-bridge/docs/deployment-topology-spec.md) — Rolling upgrades and version safety
- [Execution Plane Hardening Spec](./openclaw-bridge/docs/execution-plane-hardening-spec.md) — Container execution policy enforcement scaffolding
- [Execution Plane Activation Spec](./openclaw-bridge/docs/execution-plane-activation-spec.md) — Layered runtime enablement controls
- [Execution Threat Model](./openclaw-bridge/docs/threat-model.md) — Container breakout and supply chain threat libraries
- [Secret Governance](./openclaw-bridge/docs/secret-governance.md) — Runtime secret injection and leakage prevention
- [Cluster Simulation Spec](./openclaw-bridge/docs/cluster-simulation-spec.md) — Multi-node fault injection harness
- [Topology Model](./openclaw-bridge/deployment/topology-model.md) — Production topology model and node placement guidance
- [Operational Playbook](./openclaw-bridge/deployment/operational-playbook.md) — Playbooks for disaster recovery and performance targets
- [Bridge Setup & Operations](./openclaw-bridge/SETUP.md)
- [Bridge API Contract](./openclaw-bridge/docs/API.md)
- [Burp Integration](./openclaw-bridge/docs/BURP_INTEGRATION.md)
- [LLDB Triage Flow](./openclaw-bridge/docs/LLDB_TRIAGE.md)
- [Operations Guide](./openclaw-bridge/docs/OPERATIONS.md)

## Safety Notes

- Keep `.env` files local-only and uncommitted.
- Keep bindings on loopback (`127.0.0.1`) unless you intentionally harden for remote use.
- Treat the root of this repository (`/Users/trevorrobey/AI-Agent-BountyHunt`) as the active workspace root.
