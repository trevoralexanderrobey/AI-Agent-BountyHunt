# OpenClaw Bridge Setup (Current)

Canonical stack root:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge`

This file describes the current architecture and the operational path that is working now.

## 1) Architecture Overview

Core runtime services:
- Ollama API: `http://localhost:11434/v1`
- OpenClaw bridge: `http://127.0.0.1:8787`
- MCP server: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/dist/server.js`
- OpenCode daemon: `http://127.0.0.1:8091`
- OpenCode internal server: `http://127.0.0.1:8090`

Current default model:
- `qwen2.5-coder:7b`

Runtime skill load path:
- `/Users/trevorrobey/.openclaw/skills`

Repo skill source path:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills`

## 2) Required Software

Install/verify:

```bash
# Node + npm
node -v
npm -v

# PM2
pm2 -v

# Python + Jinja2 (for Skill Spawner)
python3 --version
python3 -c "import jinja2; print(jinja2.__version__)"

# Docker (for Kali skill execution)
docker --version

# Ollama
ollama --version

# OpenCode CLI
opencode --version
```

If missing:

```bash
npm install -g pm2
pip3 install jinja2
brew install --cask docker
brew install anomalyco/tap/opencode
```

## 3) Model Baseline

```bash
ollama pull qwen2.5-coder:7b
ollama list
```

Expected: `qwen2.5-coder:7b` present.

## 4) Environment File

Local env file:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/.env`

Key values currently expected:
- `BRIDGE_PORT=8787`
- `BRIDGE_HTTP=true`
- `OPENCLAW_GATEWAY_BASE_URL=http://localhost:11434/v1`
- `OPENCLAW_DEFAULT_MODEL=qwen2.5-coder:7b`
- `OPENCLAW_BRIDGE_BASE_URL=http://127.0.0.1:8787`
- `OPENCODE_SERVER_BASE_URL=http://127.0.0.1:8090`
- `OPENCODE_DAEMON_BASE_URL=http://127.0.0.1:8091`
- `OPENCODE_MAX_ACTIVE_SESSIONS=2`
- `OPENCODE_QUEUE_MAX=8`

Do not commit `.env`.

## 5) Build

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"
npm install
npm run bridge:build

cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp"
npm install
npm run build
```

## 5b) Generate Skills (Skill Spawner)

Generate new tool skills from Kali tool names:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"

# Generate a CLI skill (headless-kali mode)
python3 scripts/spawner.py nmap --flags "-sV -sC"

# Preview without writing files or running hooks
python3 scripts/spawner.py dirb --dry-run

# Overwrite an existing skill
python3 scripts/spawner.py nmap --force

# Skip bridge restart after generation
python3 scripts/spawner.py nikto --no-restart-bridge
```

Generated skills include the full TSP v2/v3 runtime (lossless storage, semantic clustering, anomaly extraction, cross-job diff, baseline tagging).

See: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/docs/skill-runtime-v1.md`

## 6) Start/Restart (PM2 Recommended)

Use this as the primary operational entrypoint:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp"
./scripts/mcp-start-pm2.sh
```

This script:
- sources env from `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/.env` (or local MCP `.env`)
- syncs skills via `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/scripts/sync-skill-to-runtime.sh`
- starts/restarts PM2 apps
- saves PM2 state

Check status/logs:

```bash
pm2 status openclaw-bridge openclaw-mcp openclaw-opencode-daemon
pm2 logs openclaw-bridge --lines 80
pm2 logs openclaw-mcp --lines 80
pm2 logs openclaw-opencode-daemon --lines 80
```

Stop all:

```bash
pm2 stop openclaw-bridge openclaw-mcp openclaw-opencode-daemon
```

## 7) LaunchAgent Mode (Optional Alternative)

Generate plists from current repo location:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp"
./scripts/mcp-install-launchd.sh
```

Generated files:
- `/Users/trevorrobey/Library/LaunchAgents/com.openclaw.bridge.plist`
- `/Users/trevorrobey/Library/LaunchAgents/com.openclaw.mcp.plist`
- `/Users/trevorrobey/Library/LaunchAgents/com.openclaw.opencode-daemon.plist`

Important:
- Use either PM2 or LaunchAgents for these services, not both simultaneously.

## 8) Client Wiring

### 8.1 Codex / VS Code

Workspace MCP config:
- `/Users/trevorrobey/AI-Agent-BountyHunt/.vscode/mcp.json`

Server command points to:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/dist/server.js`

### 8.2 Qwen

Qwen config files:
- `/Users/trevorrobey/Library/Application Support/Qwen/settings.json`
- `/Users/trevorrobey/Library/Application Support/Qwen/Local Storage/leveldb`

Qwen OpenClaw bootstrap command path:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/scripts/qwen-openclaw-bootstrap.sh`

SSE endpoint (bridge-native MCP):
- `http://127.0.0.1:8787/mcp/sse`

### 8.3 Antigravity

Source-of-truth folder:
- `/Users/trevorrobey/Google Antigravity/AG client for OpenClaw (source of truth)`

Runtime bundle folder:
- `/Users/trevorrobey/AI-Agent-BountyHunt/AG for OC`

Antigravity bootstrap command path:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/scripts/antigravity-openclaw-bootstrap.sh`

Installed Antigravity MCP file:
- `/Users/trevorrobey/Library/Application Support/Antigravity/User/mcp.json`

Deploy source-of-truth to runtime and install:

```bash
cd "/Users/trevorrobey/Google Antigravity/AG client for OpenClaw (source of truth)"
./deploy-to-runtime.sh "/Users/trevorrobey/AI-Agent-BountyHunt/AG for OC"
```

## 9) Verification

```bash
# services
pm2 status openclaw-bridge openclaw-mcp openclaw-opencode-daemon

# bridge
curl -sS http://127.0.0.1:8787/health | jq

# mcp sse
curl -N http://127.0.0.1:8787/mcp/sse

# opencode daemon
curl -sS http://127.0.0.1:8091/health | jq
curl -sS http://127.0.0.1:8091/metrics

# ollama
curl -sS http://localhost:11434/v1/models | jq
```

## 10) Troubleshooting

If bridge is not listening on `8787`:
- `pm2 logs openclaw-bridge --lines 120`
- ensure no duplicate supervisor ownership (LaunchAgent + PM2 conflict)

If daemon is failing/restarting:
- `pm2 logs openclaw-opencode-daemon --lines 120`
- `opencode --version`

If skill tools fail with “Tools module not found”:
- run `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/scripts/sync-skill-to-runtime.sh`
- restart via `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/scripts/mcp-start-pm2.sh`

If client still references old paths:
- check Qwen files above
- check Antigravity `mcp.json` path above
- re-run client deployment/install scripts

## 11) Security Baseline

- Keep services loopback-only (`127.0.0.1`).
- Keep `.env` local and private.
- Keep mutation/active-scan flags disabled unless intentionally needed.

## 12) Workspace Boundary

Active project/workspace root for this stack:
- `/Users/trevorrobey/AI-Agent-BountyHunt`

Do not treat `/Volumes/ExtraCurricular/My Digital Garden` as the active OpenClaw runtime root for this stack.
