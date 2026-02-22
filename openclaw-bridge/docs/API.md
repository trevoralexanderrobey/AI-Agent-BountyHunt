# Bridge API Contract

Base URL (default):
- `http://127.0.0.1:8787` (local dev mode with `BRIDGE_HTTP=true`).

If TLS is enabled (`BRIDGE_HTTP=false`) and you have installed/trusted the self-signed cert, use `https://127.0.0.1:8787` instead. All endpoints are local-only, intended for `127.0.0.1`.

## `GET /health`

Returns a JSON object describing service health and integration reachability.

Example (local dev HTTP):

```bash
curl -s http://127.0.0.1:8787/health | jq
```

## `POST /jobs`

Queues a new job and returns a `JobRecord`.

Request body:

```json
{
  "instruction": "plain-language task (required)",
  "repo_url": "https://github.com/owner/repo (optional)",
  "context_urls": ["https://... (optional)"],
  "hints": "optional",
  "branch_name": "optional",
  "model": "optional",
  "requester": "codex (optional, default: codex)",
  "gateway_base_url": "https://127.0.0.1:18789/v1 (optional override)",
  "auth_token": "optional override; otherwise bridge reads from ~/.openclaw/openclaw.json"
}
```

Example:

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  https://127.0.0.1:8787/jobs \
  -d '{
    "instruction": "Analyze this repo and propose the smallest safe fix",
    "repo_url": "https://github.com/openclaw/openclaw",
    "context_urls": ["https://github.com/openclaw/openclaw/issues/1"],
    "hints": "Prefer minimal diffs and add tests if missing",
    "requester": "codex"
  }'
```

Artifacts:
- `${BRIDGE_WORKSPACE_ROOT}/jobs/<jobId>/MISSION_INPUT.json`
- `${BRIDGE_WORKSPACE_ROOT}/jobs/<jobId>/MISSION_LOG.ndjson`
- `${BRIDGE_WORKSPACE_ROOT}/jobs/<jobId>/MISSION_REPORT.md`

## `GET /jobs`

Returns the most recent jobs from the state store.

Example:

```bash
curl -s http://127.0.0.1:8787/jobs
```

## `GET /jobs/:id`

Returns a single job by id.

Example:

```bash
curl -s http://127.0.0.1:8787/jobs/job-123
```

## `POST /jobs/:id/cancel`

Cancels a queued/running job (best-effort).

Example:

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/jobs/job-123/cancel \
  -d '{}'
```

## `POST /execute-tool`

Runs a tool in one of two modes:

1) **Skill tool mode** (calls `~/.openclaw/skills/<skill>/tools.js`):
- include `skill`

2) **Burp tool mode** (forwards to BionicLink server inside Burp):
- omit `skill`
- only allowlisted tools are available: `burp_get_history`, `burp_analyze_request`, `burp_active_scan`

### Request Body

```json
{
  "skill": "optional-skill-name",
  "tool": "tool_name",
  "args": { "any": "json" }
}
```

### Example: Call a Skill Tool

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/execute-tool \
  -d '{
    "skill": "bounty-hunter",
    "tool": "git_clone",
    "args": { "repo_url": "https://github.com/openclaw/openclaw" }
  }'
```

### Example: Burp History (TSP summarized)

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/execute-tool \
  -d '{
    "tool": "burp_get_history",
    "args": { "limit": 25, "inScope": true }
  }'
```

### Example: Burp Repeater (Scope-locked)

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/execute-tool \
  -d '{
    "tool": "burp_analyze_request",
    "args": {
      "url": "https://example.com/",
      "method": "GET",
      "headers": { "X-Bug-Bounty": "True" }
    }
  }'
```

### Example: Burp Active Scan (Guarded)

`burp_active_scan` is blocked unless:
- the target is in Burp scope (Scope Lock)
- `BURP_ALLOW_ACTIVE_SCAN=true` in `openclaw-bridge/.env`

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  https://127.0.0.1:8787/execute-tool \
  -d '{
    "tool": "burp_active_scan",
    "args": { "url": "https://in-scope.example/" }
  }'
```

## MCP SSE endpoint (Qwen-compatible)

The bridge now exposes a local MCP-over-SSE transport:

- `GET /mcp/sse` (alias: `GET /mcp/events`) to establish the SSE stream
- `POST /mcp/messages?sessionId=<id>` for client JSON-RPC messages

Notes:
- Bridge auth is shared. If `BRIDGE_AUTH_TOKEN` is set, both endpoints require `Authorization: Bearer <token>`.
- The SSE stream sends the required `endpoint` event with the message POST URL.
- Keepalive comments are emitted periodically (`MCP_SSE_KEEPALIVE_MS`, default `15000`).

### Example: open stream and inspect handshake

```bash
curl -N http://127.0.0.1:8787/mcp/sse
```

Expected first event includes a relative message endpoint:

```text
event: endpoint
data: /mcp/messages?sessionId=<uuid>
```

### Example: auth-protected stream

```bash
curl -N \
  -H "Authorization: Bearer $BRIDGE_AUTH_TOKEN" \
  http://127.0.0.1:8787/mcp/sse
```

### Qwen JSON (SSE)

```json
{
  "name": "Local OpenClaw MCP",
  "description": "OpenClaw bridge MCP server (local dev)",
  "type": "SSE",
  "url": "http://127.0.0.1:8787/mcp/sse"
}
```

## OpenCode daemon API (local skill backend)

The OpenCode daemon is a loopback-only service used by the `opencode` skill wrapper:

- Base URL: `http://127.0.0.1:8091`
- Primary backend: `opencode serve` at `http://127.0.0.1:8090`
- Fallback backend: `opencode run --session ...`

### `GET /health`

Returns daemon health, queue state, and OpenCode server status.

```bash
curl -s http://127.0.0.1:8091/health | jq
```

### `POST /session`

Creates a daemon session.

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8091/session \
  -d '{"session_id":"my-session","title":"manual test"}'
```

### `POST /session/:id/message`

Sends a message to a session.

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8091/session/my-session/message \
  -d '{"message":"Say: OpenCode daemon OK"}'
```

### `GET /session/:id/state`

Fetches current session state and recent history.

```bash
curl -s http://127.0.0.1:8091/session/my-session/state | jq
```

### `POST /session/:id/close`

Closes and removes a session.

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8091/session/my-session/close \
  -d '{}'
```

### `GET /metrics`

Prometheus metrics for queue/session/fallback counters.

```bash
curl -s http://127.0.0.1:8091/metrics
```

## `POST /lldb-stop`

Creates a new job from an LLDB stop event (defensive crash triage).

Notes:
- Local-only endpoint (`127.0.0.1`).
- `event` must be a JSON object.
- Payload size is capped (200 KiB) to avoid runaway logs.
- The resulting job writes `LLDB_STOP_EVENT.json` into the job workspace and generates a `MISSION_REPORT.md`.

Request body:

```json
{
  "event": { "any": "json object (required)" },
  "instruction": "optional override",
  "requester": "optional override (default: lldb)",
  "model": "optional (used only by http transport)"
}
```

Example:

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/lldb-stop \
  -d '{
    "event": {
      "timestamp": "2026-02-14T08:00:00Z",
      "pid": 12345,
      "triple": "arm64-apple-macosx",
      "registers": { "pc": "0xdeadbeef" },
      "backtrace": [{ "index": 0, "pc": "0xdeadbeef", "symbol": "crash_here" }]
    }
  }'
```

## `POST /bionic-ingest`

Creates a new job from a Burp/BionicLink HTTP request/response capture for defensive protocol stability analysis.

Notes:
- Local-only endpoint (`127.0.0.1`).
- Inbound payload is normalized and common secret headers are redacted (`Authorization`, `Cookie`, `Set-Cookie`, etc).
- Payload size is capped (200 KiB after normalization).
- The resulting job writes `BIONIC_INGEST_EVENT.json` into the job workspace and generates a `MISSION_REPORT.md`.

Request body (typical payload shape):

```json
{
  "url": "https://example.com/api",
  "method": "POST",
  "request_headers": [{ "name": "Content-Type", "value": "application/json" }],
  "request_body": "{\"hello\":\"world\"}",
  "status": 200,
  "response_headers": [{ "name": "Content-Type", "value": "application/json" }],
  "response_body": "{\"ok\":true}"
}
```

Optional wrapper fields (if you want to override job fields):

```json
{
  "instruction": "optional override",
  "requester": "optional override (default: bioniclink)",
  "model": "optional",
  "packet": { "url": "https://...", "method": "GET" }
}
```

Example:

```bash
curl --fail --silent --show-error \
  -H "Content-Type: application/json" \
  -X POST \
  http://127.0.0.1:8787/bionic-ingest \
  -d '{
    "url": "https://example.com/api/submit",
    "method": "POST",
    "request_headers": [{ "name": "Content-Length", "value": "999999999999999999999999" }],
    "request_body": "bplist00...",
    "status": 400,
    "response_headers": [{ "name": "Content-Type", "value": "text/plain" }],
    "response_body": "bad request"
  }'
```
