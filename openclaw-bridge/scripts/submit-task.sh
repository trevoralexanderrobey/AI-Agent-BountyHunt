#!/usr/bin/env bash
set -euo pipefail

bridge_base_url="${BRIDGE_BASE_URL:-http://127.0.0.1:8787}"
instruction=""
repo_url=""
hints=""
branch_name=""
model=""
requester="codex"
contexts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --instruction)
      instruction="${2:-}"
      shift 2
      ;;
    --repo)
      repo_url="${2:-}"
      shift 2
      ;;
    --context)
      contexts+=("${2:-}")
      shift 2
      ;;
    --hints)
      hints="${2:-}"
      shift 2
      ;;
    --branch)
      branch_name="${2:-}"
      shift 2
      ;;
    --model)
      model="${2:-}"
      shift 2
      ;;
    --requester)
      requester="${2:-codex}"
      shift 2
      ;;
    --bridge)
      bridge_base_url="${2:-}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: scripts/submit-task.sh --instruction \"text\" [--repo URL] [--context URL]... [--hints text] [--branch name] [--model model] [--requester codex|cli|<tag>] [--bridge URL]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$instruction" ]]; then
  echo "--instruction is required"
  exit 1
fi

contexts_json="[]"
if [[ ${#contexts[@]} -gt 0 ]]; then
  contexts_json=$(printf '%s\n' "${contexts[@]}" | node -e '
const fs = require("node:fs");
const items = fs.readFileSync(0, "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
process.stdout.write(JSON.stringify(items));
')
fi

payload=$(node -e '
const payload = {
  instruction: process.argv[1],
  requester: process.argv[2],
};
const repo = process.argv[3];
const contexts = JSON.parse(process.argv[4]);
const hints = process.argv[5];
const branch = process.argv[6];
const model = process.argv[7];
if (repo) payload.repo_url = repo;
if (Array.isArray(contexts) && contexts.length > 0) payload.context_urls = contexts;
if (hints) payload.hints = hints;
if (branch) payload.branch_name = branch;
if (model) payload.model = model;
process.stdout.write(JSON.stringify(payload));
' "$instruction" "$requester" "$repo_url" "$contexts_json" "$hints" "$branch_name" "$model")

curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  "${bridge_base_url%/}/jobs" \
  -d "$payload"

echo
