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
- [Bridge Setup & Operations](./openclaw-bridge/SETUP.md)
- [Bridge API Contract](./openclaw-bridge/docs/API.md)
- [Burp Integration](./openclaw-bridge/docs/BURP_INTEGRATION.md)
- [LLDB Triage Flow](./openclaw-bridge/docs/LLDB_TRIAGE.md)
- [Operations Guide](./openclaw-bridge/docs/OPERATIONS.md)

## Safety Notes

- Keep `.env` files local-only and uncommitted.
- Keep bindings on loopback (`127.0.0.1`) unless you intentionally harden for remote use.
- Treat the root of this repository (`/Users/trevorrobey/AI-Agent-BountyHunt`) as the active workspace root.
