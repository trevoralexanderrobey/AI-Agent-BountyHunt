#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_DIR="${ROOT_DIR}/skills"
RUNTIME_SKILLS_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
TMP_PARENT="${RUNTIME_SKILLS_DIR}/.tmp"
declare -a SKILLS_TO_SYNC
if [[ "$#" -gt 0 ]]; then
  SKILLS_TO_SYNC=("$@")
else
  SKILLS_TO_SYNC=(
    "opencode"
    "find-skills"
    "self-improving-agent"
  )
fi

if [[ ! -d "${SKILLS_DIR}" ]]; then
  echo "Skills directory not found: ${SKILLS_DIR}" >&2
  exit 1
fi

mkdir -p "${RUNTIME_SKILLS_DIR}" "${TMP_PARENT}"

sync_one_skill() {
  local skill="$1"
  local src_dir="${SKILLS_DIR}/${skill}"
  local dest_dir="${RUNTIME_SKILLS_DIR}/${skill}"
  local tmp_dir="${TMP_PARENT}/${skill}.$$"
  local swap_dir="${RUNTIME_SKILLS_DIR}/.${skill}.new"

  if [[ ! -d "${src_dir}" ]]; then
    echo "Source skill directory not found: ${src_dir}" >&2
    exit 1
  fi

  if [[ ! -f "${src_dir}/tools.js" ]]; then
    echo "tools.js missing for skill: ${skill} (${src_dir})" >&2
    exit 1
  fi

  rm -rf "${tmp_dir}" "${swap_dir}"
  mkdir -p "${tmp_dir}"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "${src_dir}/" "${tmp_dir}/"
  else
    cp -R "${src_dir}/." "${tmp_dir}/"
  fi

  mv "${tmp_dir}" "${swap_dir}"
  rm -rf "${dest_dir}"
  mv "${swap_dir}" "${dest_dir}"
  echo "Synced ${skill} to ${dest_dir}"
}

for skill in "${SKILLS_TO_SYNC[@]}"; do
  sync_one_skill "${skill}"
done
