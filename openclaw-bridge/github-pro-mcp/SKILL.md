---
name: github-pro-openclaw-bridge
version: 0.1.0
description: MCP bridge enabling GitHub Pro Agent Mode to delegate high-privilege tasks to OpenClaw
author: Trevor Robey
requires:
  bins: [node, openclaw]
  env: []
  optional_env:
    - OPENCLAW_TRANSPORT        # cli (default) or http
    - OPENCLAW_GATEWAY_BASE_URL # stack default http://localhost:11434/v1
    - OPENCLAW_DEFAULT_MODEL    # stack default qwen2.5-coder:7b
    - OPENCLAW_TIMEOUT_MS       # default 180000
    - OPENCLAW_BRIDGE_BASE_URL  # stack default http://127.0.0.1:8787
    - BIONICLINK_BASE_URL       # default https://127.0.0.1:8090
    - BOUNTY_HUNTER_ALLOW_MUTATIONS  # gate for bounty-hunter skill mutations
    - H1_ALLOW_MUTATIONS             # gate for hackerone-researcher mutations
    - BURP_ALLOW_ACTIVE_SCAN         # gate for Burp active scanning
    - BURP_ALLOW_RAW_DATA            # gate for raw request/response data
models:
  - qwen2.5-coder:7b    # Local Ollama model (stack default)
  - openclaw-gpt-4o     # GPT-4o via OpenClaw gateway
---

# GitHub Pro → OpenClaw Bridge Skill

## Architecture: Director / Executor

This skill implements a **Director → Executor** pattern:

- **Director** (GitHub Pro Agent Mode): Reasons about *what* needs to be done. Uses Claude 3.5 Sonnet or GPT-4o from the GitHub Pro subscription. Reads code, plans tasks, and decides when to delegate work.
- **Executor** (OpenClaw): Handles *how* privileged operations are performed. In this stack it uses local Ollama (`http://localhost:11434/v1`) with bridge-backed tools on `http://127.0.0.1:8787`.

### When GitHub Pro Should Delegate to OpenClaw

| Scenario | Tool to Use | Why Delegate |
|----------|-------------|--------------|
| Run autonomous bounty work | `openclaw_exec` | Needs git clone, code changes, test execution, PR creation |
| Execute shell commands outside sandbox | `openclaw_terminal` | GitHub Pro's terminal is sandboxed; this bypasses it |
| Submit long-running background work | `job_submit` | Async processing with mission reports |
| Run a specific skill tool | `execute_skill_tool` | Dynamic tool loading from ClawHub |
| Inspect Burp proxy traffic | `burp_get_history` | Requires BionicLink extension communication |
| Analyze HTTP requests | `burp_analyze_request` | Sends through Burp Repeater with scope validation |
| Trigger security scans | `burp_active_scan` | Gated, requires scope lock + env var |
| Triage a crash | `lldb_triage` | Creates async triage job with agent analysis |
| Analyze HTTP pair stability | `bionic_ingest` | Server-side precheck + async agent analysis |

### When GitHub Pro Should Handle Directly

- Reading/editing files in the workspace
- Code explanation, documentation, refactoring
- Git status, diff, log inspection
- Simple terminal commands that don't need elevated access
- Obsidian vault operations (use the Obsidian REST API)

## MCP Tools (15 total)

### OpenClaw Direct (2)

- **`openclaw_exec`** — Send a prompt to the OpenClaw agent. Returns the agent's response text. Supports model override, session continuity, and custom system prompts.
- **`openclaw_terminal`** — Execute a shell command with full system access. Returns stdout, stderr, and exit code.

### Job Queue (4)

- **`job_submit`** — Submit a background job (instruction + optional repo URL, hints, context URLs). Returns job ID.
- **`job_list`** — List all jobs (most recent first) with status.
- **`job_status`** — Get details for a specific job by ID.
- **`job_cancel`** — Cancel a queued/running job.

### ClawHub Skills (3)

- **`skill_list`** — List installed skills from `~/.openclaw/skills/` with their available tools.
- **`skill_info`** — Read the SKILL.md manifest for a specific skill.
- **`execute_skill_tool`** — Execute a named function from a skill's `tools.js` with arguments.

### Burp Suite Integration (4)

- **`burp_get_history`** — Get proxy history (summarized, deduplicated). No gate.
- **`burp_analyze_request`** — Send request through Repeater with scope check. No gate.
- **`burp_active_scan`** — Start active audit. **GATED:** `BURP_ALLOW_ACTIVE_SCAN=true`.
- **`burp_get_raw_request`** — Get raw request/response data. **GATED:** `BURP_ALLOW_RAW_DATA=true`.

### Triage (2)

- **`lldb_triage`** — Submit LLDB crash event for async agent triage.
- **`bionic_ingest`** — Submit HTTP pair for stability analysis with server-side prechecks.

## Safety Controls

### Mutation Gates

Operations that create external side effects are gated behind env vars:

| Gate | Default | Controls |
|------|---------|----------|
| `BOUNTY_HUNTER_ALLOW_MUTATIONS` | `false` | `gh_handshake`, `bountifi_submit`, `gh_settle` in bounty-hunter skill |
| `H1_ALLOW_MUTATIONS` | `false` | HackerOne report submission in hackerone-researcher skill |
| `BURP_ALLOW_ACTIVE_SCAN` | `false` | `burp_active_scan` tool |
| `BURP_ALLOW_RAW_DATA` | `false` | `burp_get_raw_request` tool |

### Scope Lock

All Burp tools validate URLs against Burp's Target Scope before executing. Out-of-scope requests are rejected with a clear error.

### Safety Prompts

- LLDB triage: "Do not provide exploit, weaponization, or payload guidance."
- Bionic ingest: "Do NOT generate weaponized exploit payloads or shellcode."
- Generic tasks: "Do not provide exploit, weaponization, or authentication bypass guidance."

## Model Compatibility

The Director (GitHub Pro) model can be any model available in your GitHub Pro plan:
- **Claude 3.5 Sonnet** — Strong at code generation, reasoning, and security analysis.
- **GPT-4o** — Strong at broad knowledge, planning, and multi-step orchestration.

The Executor (OpenClaw) model is configurable per-call via the `model` parameter:
- `qwen2.5-coder:7b` (default) — Local model via Ollama.
- `openclaw-sonnet-4` — Maps to Claude 3.5 Sonnet through the cloud gateway.
- `openclaw-gpt-4o` — Maps to GPT-4o through the cloud gateway.

The stack default is local Ollama (`http://localhost:11434/v1`).
To use cloud models, pass `gateway_base_url: "http://127.0.0.1:18789/v1"` per call.

## Examples

### Delegate bounty work
```
Use openclaw_exec to fix the bug described in issue #42 of repo https://github.com/example/project.
The fix should pass all existing tests.
```

### List available skills
```
Use skill_list to show me what OpenClaw skills are installed.
```

### Check Burp traffic
```
Use burp_get_history with in_scope=true to show recent in-scope proxy traffic.
```

### Submit background job
```
Use job_submit with instruction "Audit the authentication flow in the target app" and requester "github-pro".
```
