#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_MCP="${SCRIPT_DIR}/mcp.json"
ANTIGRAVITY_USER_DIR="${ANTIGRAVITY_USER_DIR:-$HOME/Library/Application Support/Antigravity/User}"
TARGET_MCP="${ANTIGRAVITY_USER_DIR}/mcp.json"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

if [[ ! -f "${SOURCE_MCP}" ]]; then
  echo "Missing source MCP file: ${SOURCE_MCP}" >&2
  echo "Run deploy-to-runtime.sh first (or copy mcp.template.json to mcp.json)." >&2
  exit 1
fi

mkdir -p "${ANTIGRAVITY_USER_DIR}"
if [[ -f "${TARGET_MCP}" ]]; then
  cp "${TARGET_MCP}" "${TARGET_MCP}.bak.${TIMESTAMP}"
fi

cp "${SOURCE_MCP}" "${TARGET_MCP}"
echo "Installed OpenClaw MCP config to ${TARGET_MCP}"
