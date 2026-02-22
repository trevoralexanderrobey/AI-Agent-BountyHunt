#!/usr/bin/env bash
set -euo pipefail
# Generate user LaunchAgents for MCP and OpenCode daemon using env vars from .env (if present).

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLIST_DIR="$HOME/Library/LaunchAgents"
MCP_PLIST_PATH="$PLIST_DIR/com.openclaw.mcp.plist"
DAEMON_PLIST_PATH="$PLIST_DIR/com.openclaw.opencode-daemon.plist"
BRIDGE_PLIST_PATH="$PLIST_DIR/com.openclaw.bridge.plist"
NODE_BIN="${NODE_BIN:-/opt/homebrew/bin/node}"
DAEMON_CWD="$ROOT_DIR/../skills/opencode-daemon"
BRIDGE_CWD="$ROOT_DIR/.."
ENV_FILE="$ROOT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  ENV_FILE="$ROOT_DIR/../.env"
fi

if [ ! -x "$NODE_BIN" ]; then
  NODE_BIN="$(command -v node || true)"
fi

if [ -z "${NODE_BIN}" ] || [ ! -x "${NODE_BIN}" ]; then
  echo "Unable to locate a usable node binary (checked /opt/homebrew/bin/node and PATH)." >&2
  exit 1
fi

mkdir -p "$PLIST_DIR"

ENV_CONTENT=""
if [ -f "$ENV_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in
      ""|\#*) continue ;;
    esac
    key=$(echo "$line" | cut -d= -f1)
    val=$(echo "$line" | cut -d= -f2-)
    ENV_CONTENT="$ENV_CONTENT
      <key>$key</key>
      <string>$val</string>"
  done < "$ENV_FILE"
fi

write_plist() {
  local label="$1"
  local plist_path="$2"
  local working_dir="$3"
  local script_path="$4"
  local stdout_log="$5"
  local stderr_log="$6"

  cat > "$plist_path" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE_BIN</string>
    <string>$script_path</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>$working_dir</string>
  <key>StandardOutPath</key>
  <string>$stdout_log</string>
  <key>StandardErrorPath</key>
  <string>$stderr_log</string>
  <key>EnvironmentVariables</key>
  <dict>
      <key>PATH</key>
      <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>$ENV_CONTENT
  </dict>
</dict>
</plist>
EOF2
}

write_plist \
  "com.openclaw.mcp" \
  "$MCP_PLIST_PATH" \
  "$ROOT_DIR" \
  "$ROOT_DIR/dist/server.js" \
  "$HOME/Library/Logs/openclaw-mcp.log" \
  "$HOME/Library/Logs/openclaw-mcp.err.log"

write_plist \
  "com.openclaw.opencode-daemon" \
  "$DAEMON_PLIST_PATH" \
  "$DAEMON_CWD" \
  "$DAEMON_CWD/server.js" \
  "$HOME/Library/Logs/openclaw-opencode-daemon.log" \
  "$HOME/Library/Logs/openclaw-opencode-daemon.err.log"

write_plist \
  "com.openclaw.bridge" \
  "$BRIDGE_PLIST_PATH" \
  "$BRIDGE_CWD" \
  "$BRIDGE_CWD/dist/bridge/server.js" \
  "$HOME/Library/Logs/openclaw-bridge.log" \
  "$HOME/Library/Logs/openclaw-bridge.err.log"

echo "Wrote $MCP_PLIST_PATH"
echo "Wrote $DAEMON_PLIST_PATH"
echo "Wrote $BRIDGE_PLIST_PATH"
echo "To load MCP: launchctl unload $MCP_PLIST_PATH 2>/dev/null || true; launchctl load $MCP_PLIST_PATH"
echo "To load OpenCode daemon: launchctl unload $DAEMON_PLIST_PATH 2>/dev/null || true; launchctl load $DAEMON_PLIST_PATH"
echo "To load OpenClaw bridge: launchctl unload $BRIDGE_PLIST_PATH 2>/dev/null || true; launchctl load $BRIDGE_PLIST_PATH"
