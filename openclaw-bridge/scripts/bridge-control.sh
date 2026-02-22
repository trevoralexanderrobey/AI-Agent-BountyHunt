#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BRIDGE_APP_NAME="${BRIDGE_PM2_APP_NAME:-openclaw-bridge}"
ECOSYSTEM_FILE="${ROOT_DIR}/bridge-ecosystem.config.js"
ENV_FILE="${ROOT_DIR}/.env"
RUNTIME_DIR="${ROOT_DIR}/.bridge"
LOG_DIR="${RUNTIME_DIR}/logs"
BRIDGE_PID_FILE="${RUNTIME_DIR}/${BRIDGE_APP_NAME}.pid"
NOHUP_BRIDGE_OUT="${LOG_DIR}/bridge-nohup.out.log"
NOHUP_BRIDGE_ERR="${LOG_DIR}/bridge-nohup.err.log"

BRIDGE_PORT="8787"
BRIDGE_WORKSPACE_ROOT="/Users/trevorrobey/Dev/Bounties"

usage() {
  cat <<USAGE
Usage: scripts/bridge-control.sh <command>

Commands:
  start      Build and start the bridge daemon
  stop       Stop the running bridge daemon
  restart    Rebuild and restart the daemon
  status     Show process metrics and health endpoint result
  logs       Tail live bridge logs
  health     Perform only the bridge health check
USAGE
}

load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
  fi

  : "${BRIDGE_PORT:=8787}"
  : "${BRIDGE_WORKSPACE_ROOT:=/Users/trevorrobey/Dev/Bounties}"
  : "${OPENCLAW_GATEWAY_BASE_URL:=http://127.0.0.1:18789/v1}"
  : "${BOUNTY_HUNTER_ALLOW_MUTATIONS:=false}"
  : "${H1_ALLOW_MUTATIONS:=false}"

  export BRIDGE_PORT
  export BRIDGE_WORKSPACE_ROOT
  export OPENCLAW_GATEWAY_BASE_URL
  export BOUNTY_HUNTER_ALLOW_MUTATIONS
  export H1_ALLOW_MUTATIONS
}

ensure_runtime_dirs() {
  mkdir -p "${LOG_DIR}"
}

build_bridge() {
  echo "[bridge-control] Building TypeScript bridge artifacts..."
  (
    cd "${ROOT_DIR}"
    npm run bridge:build
  )
}

pm2_available() {
  command -v pm2 >/dev/null 2>&1
}

pm2_process_exists() {
  local name="$1"
  if ! pm2_available; then
    return 1
  fi

  pm2 describe "${name}" >/dev/null 2>&1
}

nohup_process_exists() {
  local pid_file="$1"
  if [[ ! -f "${pid_file}" ]]; then
    return 1
  fi

  local pid
  pid="$(cat "${pid_file}" 2>/dev/null || true)"
  [[ -n "${pid}" ]] || return 1
  kill -0 "${pid}" >/dev/null 2>&1
}

ensure_pm2_or_fallback() {
  if pm2_available; then
    return 0
  fi

  echo "[bridge-control] pm2 not found."
  if [[ -t 0 ]]; then
    local answer=""
    read -r -p "Install pm2 globally now using 'npm install -g pm2'? [Y/n] " answer
    if [[ -z "${answer}" || "${answer}" =~ ^[Yy]$ ]]; then
      if npm install -g pm2; then
        return 0
      fi
      echo "[bridge-control] pm2 installation failed. Falling back to nohup mode."
      return 1
    fi
  else
    echo "[bridge-control] Non-interactive shell detected. Falling back to nohup mode."
  fi

  return 1
}

configure_pm2_logrotate() {
  if ! pm2_available; then
    return 0
  fi

  local module_list
  module_list="$(pm2 module:list 2>/dev/null || true)"
  if [[ "${module_list}" != *"pm2-logrotate"* ]]; then
    echo "[bridge-control] Installing pm2-logrotate module..."
    pm2 install pm2-logrotate >/dev/null 2>&1 || true
  fi

  pm2 set pm2-logrotate:max_size "${PM2_LOG_MAX_SIZE:-20M}" >/dev/null 2>&1 || true
  pm2 set pm2-logrotate:retain "${PM2_LOG_RETAIN:-14}" >/dev/null 2>&1 || true
  pm2 set pm2-logrotate:compress "${PM2_LOG_COMPRESS:-true}" >/dev/null 2>&1 || true
  pm2 set pm2-logrotate:workerInterval "${PM2_LOG_WORKER_INTERVAL:-30}" >/dev/null 2>&1 || true
  pm2 set pm2-logrotate:rotateInterval "${PM2_LOG_ROTATE_INTERVAL:-0 0 * * *}" >/dev/null 2>&1 || true
}

health_check() {
  local health_url="http://127.0.0.1:${BRIDGE_PORT}/health"
  if response="$(curl --silent --show-error --max-time 3 "${health_url}" 2>/dev/null)"; then
    echo "[health] ${response}"
    return 0
  fi

  echo "[health] unavailable at ${health_url}"
  return 1
}

start_pm2() {
  configure_pm2_logrotate

  echo "[bridge-control] Starting bridge via PM2 ecosystem."
  pm2 start "${ECOSYSTEM_FILE}" --update-env >/dev/null 2>&1 || true
  pm2 restart "${BRIDGE_APP_NAME}" --update-env >/dev/null 2>&1 || true

  pm2 save >/dev/null 2>&1 || true
}

stop_pm2() {
  if pm2_process_exists "${BRIDGE_APP_NAME}"; then
    echo "[bridge-control] Stopping '${BRIDGE_APP_NAME}' (PM2)."
    pm2 stop "${BRIDGE_APP_NAME}" >/dev/null || true
    pm2 delete "${BRIDGE_APP_NAME}" >/dev/null || true
  fi

  pm2 save >/dev/null 2>&1 || true
}

status_pm2() {
  if ! pm2_process_exists "${BRIDGE_APP_NAME}"; then
    return 1
  fi

  local jlist_file
  jlist_file="$(mktemp)"
  if ! pm2 jlist >"${jlist_file}" 2>/dev/null; then
    rm -f "${jlist_file}"
    return 1
  fi

  node - "${BRIDGE_APP_NAME}" "${jlist_file}" <<'NODE'
const fs = require("node:fs");
const appNames = process.argv.slice(2, -1);
const jlistFile = process.argv[process.argv.length - 1];
const raw = fs.readFileSync(jlistFile, "utf8");
const list = JSON.parse(raw || "[]");
let foundAny = false;
for (const appName of appNames) {
  const app = list.find((entry) => entry.name === appName);
  if (!app) {
    continue;
  }
  foundAny = true;
  const now = Date.now();
  const uptimeMs = app.pm2_env && app.pm2_env.pm_uptime ? now - app.pm2_env.pm_uptime : 0;
  const uptimeSeconds = Math.max(0, Math.floor(uptimeMs / 1000));
  const cpu = app.monit && typeof app.monit.cpu === "number" ? app.monit.cpu : 0;
  const memoryBytes = app.monit && typeof app.monit.memory === "number" ? app.monit.memory : 0;
  const memoryMb = (memoryBytes / (1024 * 1024)).toFixed(1);
  const status = app.pm2_env && app.pm2_env.status ? app.pm2_env.status : "unknown";
  const restarts = app.pm2_env && typeof app.pm2_env.restart_time === "number" ? app.pm2_env.restart_time : 0;
  console.log(`manager=pm2 app=${appName} status=${status} uptime_seconds=${uptimeSeconds} cpu_percent=${cpu} memory_mb=${memoryMb} restarts=${restarts}`);
}
if (!foundAny) {
  process.exit(1);
}
NODE

  local node_status=$?
  rm -f "${jlist_file}"
  return "${node_status}"
}

start_nohup_bridge() {
  if nohup_process_exists "${BRIDGE_PID_FILE}"; then
    echo "[bridge-control] nohup bridge already running (pid $(cat "${BRIDGE_PID_FILE}"))."
    return 0
  fi

  echo "[bridge-control] Starting bridge in nohup fallback mode."
  nohup node "${ROOT_DIR}/dist/bridge/server.js" >>"${NOHUP_BRIDGE_OUT}" 2>>"${NOHUP_BRIDGE_ERR}" < /dev/null &
  local pid=$!
  echo "${pid}" >"${BRIDGE_PID_FILE}"
  disown "${pid}" >/dev/null 2>&1 || true
}

stop_nohup_bridge() {
  if ! nohup_process_exists "${BRIDGE_PID_FILE}"; then
    rm -f "${BRIDGE_PID_FILE}"
    return 0
  fi

  local pid
  pid="$(cat "${BRIDGE_PID_FILE}")"
  echo "[bridge-control] Stopping nohup bridge pid=${pid}."
  kill "${pid}" >/dev/null 2>&1 || true

  for _ in {1..20}; do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -9 "${pid}" >/dev/null 2>&1 || true
  fi

  rm -f "${BRIDGE_PID_FILE}"
}

status_nohup_bridge() {
  if ! nohup_process_exists "${BRIDGE_PID_FILE}"; then
    return 1
  fi

  local pid
  pid="$(cat "${BRIDGE_PID_FILE}")"
  local metrics
  metrics="$(ps -p "${pid}" -o etime=,%cpu=,%mem= | awk '{$1=$1;print}')"

  echo "manager=nohup app=${BRIDGE_APP_NAME} pid=${pid} metrics='${metrics}'"
}

logs_pm2() {
  touch "${LOG_DIR}/bridge-out.log" "${LOG_DIR}/bridge-error.log"
  tail -n 200 -f "${LOG_DIR}/bridge-out.log" "${LOG_DIR}/bridge-error.log"
}

logs_nohup() {
  touch "${NOHUP_BRIDGE_OUT}" "${NOHUP_BRIDGE_ERR}"
  tail -n 200 -f "${NOHUP_BRIDGE_OUT}" "${NOHUP_BRIDGE_ERR}"
}

start_command() {
  build_bridge

  if ensure_pm2_or_fallback; then
    stop_nohup_bridge
    start_pm2
  else
    start_nohup_bridge
  fi

  status_command
}

stop_command() {
  stop_pm2
  stop_nohup_bridge

  echo "[bridge-control] Bridge stopped."
}

restart_command() {
  build_bridge

  if ensure_pm2_or_fallback; then
    stop_nohup_bridge
    pm2 start "${ECOSYSTEM_FILE}" --update-env >/dev/null 2>&1 || true
    pm2 restart "${BRIDGE_APP_NAME}" --update-env >/dev/null 2>&1 || true
    pm2 save >/dev/null 2>&1 || true
  else
    stop_nohup_bridge
    start_nohup_bridge
  fi

  status_command
}

status_command() {
  local printed=0

  if status_pm2; then
    printed=1
  fi

  if status_nohup_bridge; then
    printed=1
  fi

  if [[ "${printed}" -eq 0 ]]; then
    echo "manager=none status=stopped"
  fi

  health_check || true
}

logs_command() {
  if pm2_process_exists "${BRIDGE_APP_NAME}"; then
    logs_pm2
    return
  fi

  logs_nohup
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  load_env
  ensure_runtime_dirs

  case "$1" in
    start)
      start_command
      ;;
    stop)
      stop_command
      ;;
    restart)
      restart_command
      ;;
    status)
      status_command
      ;;
    logs)
      logs_command
      ;;
    health)
      health_check
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
