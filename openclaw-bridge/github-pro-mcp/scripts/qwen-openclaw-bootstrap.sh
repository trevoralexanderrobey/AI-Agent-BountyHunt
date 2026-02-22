#!/usr/bin/env bash
set -euo pipefail

# Deterministic PATH for Qwen-launched subprocesses.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

readonly LOG_FILE="${HOME}/Library/Logs/qwen-openclaw-bootstrap.log"
readonly HEALTH_TIMEOUT_SECONDS="${QWEN_OPENCLAW_HEALTH_TIMEOUT_SECONDS:-20}"
readonly HEALTH_INTERVAL_SECONDS=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BRIDGE_ROOT="$(cd "${MCP_ROOT}/.." && pwd)"
MCP_SERVER="${MCP_ROOT}/dist/server.js"
START_SCRIPT="${MCP_ROOT}/scripts/mcp-start-pm2.sh"
ENV_FILE="${MCP_ROOT}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  ENV_FILE="${BRIDGE_ROOT}/.env"
fi

mkdir -p "$(dirname "${LOG_FILE}")"

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >>"${LOG_FILE}"
}

load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}" >/dev/null 2>&1 || true
    set +a
    log "Loaded environment from ${ENV_FILE}"
  else
    log "No env file found at ${MCP_ROOT}/.env or ${BRIDGE_ROOT}/.env"
  fi
}

check_health_url() {
  local url="$1"
  curl --silent --show-error --max-time 2 "${url}" >/dev/null 2>&1
}

services_healthy() {
  check_health_url "http://127.0.0.1:8787/health" && check_health_url "http://127.0.0.1:8091/health"
}

bootstrap_if_needed() {
  if services_healthy; then
    log "Bridge and daemon are healthy; skipping PM2 bootstrap."
    return 0
  fi

  log "Health check failed; running ${START_SCRIPT}"
  if ! "${START_SCRIPT}" >>"${LOG_FILE}" 2>&1; then
    log "PM2 bootstrap script failed"
    return 1
  fi

  local waited=0
  while (( waited < HEALTH_TIMEOUT_SECONDS )); do
    if services_healthy; then
      log "Services healthy after bootstrap (${waited}s)"
      return 0
    fi
    sleep "${HEALTH_INTERVAL_SECONDS}"
    waited=$((waited + HEALTH_INTERVAL_SECONDS))
  done

  log "Services still unhealthy after ${HEALTH_TIMEOUT_SECONDS}s timeout"
  return 1
}

main() {
  load_env

  if ! bootstrap_if_needed; then
    # Keep launching MCP so Qwen can still connect and report tool-level errors.
    log "Continuing to launch MCP server after bootstrap timeout/failure"
  fi

  log "Launching MCP stdio server: ${MCP_SERVER}"
  exec /opt/homebrew/bin/node "${MCP_SERVER}"
}

main "$@"
