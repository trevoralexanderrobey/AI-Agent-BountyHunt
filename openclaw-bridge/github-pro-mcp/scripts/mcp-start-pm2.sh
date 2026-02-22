#!/usr/bin/env bash
set -euo pipefail
# Start or restart the MCP server under pm2 using the ecosystem file.
# This script sources a local .env (if present) so environment variables persist across reboots when pm2 saves the process list.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
SYNC_SCRIPT="$ROOT_DIR/../scripts/sync-skill-to-runtime.sh"
BRIDGE_ROOT="$ROOT_DIR/.."
BRIDGE_ECOSYSTEM_FILE="$BRIDGE_ROOT/bridge-ecosystem.config.js"
ENV_FILE="$ROOT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  ENV_FILE="$ROOT_DIR/../.env"
fi

if [ -f "$ENV_FILE" ]; then
  # Export variables from .env (ignore comments and empty lines)
  set -a
  # shellcheck disable=SC1090
  source <(grep -v '^\s*#' "$ENV_FILE" | sed '/^\s*$/d') || true
  set +a
fi

if ! command -v pm2 >/dev/null 2>&1; then
  echo "pm2 not found. Install it with: npm install -g pm2" >&2
  exit 2
fi

if [ -x "$SYNC_SCRIPT" ]; then
  echo "Syncing repo skills to runtime skills directory"
  "$SYNC_SCRIPT"
fi

# If the built MCP server artifact is missing, build it so PM2 can run the dist artifact.
if [ ! -f "$ROOT_DIR/dist/server.js" ]; then
  echo "MCP dist not found; building MCP server (npm install && npm run build)"
  # Install dependencies and build (best-effort)
  npm install --prefix "$ROOT_DIR"
  npm run --prefix "$ROOT_DIR" build || true
fi

if [ ! -f "$BRIDGE_ROOT/dist/bridge/server.js" ]; then
  echo "Bridge dist not found; building bridge server (npm install && npm run bridge:build)"
  npm install --prefix "$BRIDGE_ROOT"
  npm run --prefix "$BRIDGE_ROOT" bridge:build || true
fi

echo "Starting MCP + OpenCode daemon via pm2 (ecosystem: ecosystem.config.js)"
pm2 start ecosystem.config.js --update-env || pm2 restart ecosystem.config.js --update-env || true

if [ -f "$BRIDGE_ECOSYSTEM_FILE" ]; then
  echo "Starting OpenClaw bridge via pm2 (ecosystem: bridge-ecosystem.config.js)"
  if ! pm2 start "$BRIDGE_ECOSYSTEM_FILE" --only openclaw-bridge --update-env; then
    # Recover from stale PM2 metadata after repo moves.
    pm2 delete openclaw-bridge >/dev/null 2>&1 || true
    pm2 start "$BRIDGE_ECOSYSTEM_FILE" --only openclaw-bridge --update-env || pm2 restart openclaw-bridge --update-env || true
  fi
fi

pm2 save
echo "pm2 saved process list. Use 'pm2 status openclaw-bridge openclaw-mcp openclaw-opencode-daemon' to check processes."
