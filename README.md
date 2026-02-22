# AI-Agent-BountyHunt

Bug hunting stuff and local AI agent runtime environment.

## Overview

This repository contains local environments, integrations, and bridges for running various MCP (Model Context Protocol) servers and AI agent runtimes for bug hunting against targets like Burp Suite, local source code, and local LLMs.

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
- [Bridge Setup & Operations](./openclaw-bridge/SETUP.md)
- [Bridge API Contract](./openclaw-bridge/docs/API.md)
- [Burp Integration](./openclaw-bridge/docs/BURP_INTEGRATION.md)
- [LLDB Triage Flow](./openclaw-bridge/docs/LLDB_TRIAGE.md)

## Safety Notes

- Keep `.env` files local-only and uncommitted.
- Keep bindings on loopback (`127.0.0.1`) unless you intentionally harden for remote use.
- Treat the root of this repository (`/Users/trevorrobey/AI-Agent-BountyHunt`) as the active workspace root.
