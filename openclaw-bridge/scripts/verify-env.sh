#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

required_keys=(
  "H1_API_ID"
  "H1_API_TOKEN"
  "H1_USERNAME"
)

usage() {
  cat <<USAGE
Usage: scripts/verify-env.sh

Checks that required HackerOne credentials are present in ${ENV_FILE}.
USAGE
}

extract_value() {
  local key="$1"
  local line=""

  if [[ -f "${ENV_FILE}" ]]; then
    # Supports lines like: KEY=value or export KEY=value (quotes optional).
    line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${key}=" "${ENV_FILE}" | tail -n 1 || true)"
  fi

  if [[ -z "${line}" ]]; then
    echo ""
    return 0
  fi

  line="${line#export }"
  local value="${line#*=}"
  value="$(echo "${value}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  # Strip surrounding quotes if present.
  if [[ "${value}" =~ ^\".*\"$ ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "${value}" =~ ^\'.*\'$ ]]; then
    value="${value:1:${#value}-2}"
  fi

  echo "${value}"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ ! -f "${ENV_FILE}" ]]; then
    echo "[verify-env] WARNING: .env file not found at ${ENV_FILE}"
    echo "[verify-env] Create it from .env.example and set HackerOne credentials."
    echo "[verify-env] These keys are required for Hacker API v1 authentication (HTTP Basic Auth)."
    # [cite_start] These keys are required for Hacker API v1 HTTP Basic Auth. [cite: 417-422]
    exit 1
  fi

  local missing=()
  for key in "${required_keys[@]}"; do
    local value
    value="$(extract_value "${key}")"
    if [[ -z "${value}" ]]; then
      missing+=("${key}")
    fi
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "[verify-env] WARNING: Missing required HackerOne credential(s) in ${ENV_FILE}:"
    for key in "${missing[@]}"; do
      echo "  - ${key}"
    done
    echo "[verify-env] These keys are required for Hacker API v1 authentication (HTTP Basic Auth)."
    # [cite_start] These keys are required for Hacker API v1 authentication (HTTP Basic Auth). [cite: 417-422]
    exit 1
  fi

  echo "[verify-env] OK: Required HackerOne credentials are present in ${ENV_FILE}."
}

main "$@"
