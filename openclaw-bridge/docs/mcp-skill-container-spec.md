# MCP Skill Container Spec (PoC)

This document defines the proof-of-concept MCP boundary for running one distributed skill container (`nmap`) using Skill Runtime v1.

## Server Endpoint

- Protocol: JSON-RPC 2.0 over HTTP
- Method: `POST`
- Path: `/mcp`
- Default port: `4000`
- Port config: `PORT` environment variable

## Startup Requirements (Fail-Fast)

The server will refuse to start and exit with non-zero status when any required environment variable is missing:

- `TOOL_NAME`
- `SKILL_SLUG`
- `MCP_SKILL_TOKEN`

`MCP_SKILL_TOKEN` has no Dockerfile default and must be provided at runtime.

## Runtime Binding

The MCP server initializes the runtime with:

```js
createSkillRuntime({
  slug: process.env.SKILL_SLUG,
  toolName: process.env.TOOL_NAME,
  defaultFlags: "",
  injectHostNet: false,
});
```

## Transport Security Rules

- Only `POST /mcp` is accepted.
- `Content-Type` base media type must be `application/json`.
- Bearer authentication is required before request body parsing:
  - `Authorization: Bearer <MCP_SKILL_TOKEN>`
- Invalid/missing auth returns plain HTTP `401 Unauthorized` (no JSON-RPC envelope).
- Request bodies are streamed and capped at `1MB`; over-limit requests are terminated by socket destroy.
- Runtime method execution timeout defaults to `60000ms` and can be overridden via `SKILL_EXECUTION_TIMEOUT_MS`.

## Method Whitelist (Skill Runtime v1 only)

The server exposes only these methods:

- `run`
- `health`
- `read_output_chunk`
- `search_output`
- `semantic_summary`
- `anomaly_summary`
- `anomaly_diff`
- `tag_baseline`
- `list_baselines`
- `diff_against_baseline`

Any other method returns JSON-RPC `-32601 Method Not Found`.

## JSON-RPC Request/Response

### Request format

```json
{
  "jsonrpc": "2.0",
  "method": "run",
  "params": {
    "flags": "-sV",
    "target": "127.0.0.1"
  },
  "id": "req-1"
}
```

### Success response format

```json
{
  "jsonrpc": "2.0",
  "result": {
    "ok": true,
    "mode": "headless-kali"
  },
  "id": "req-1"
}
```

`result` preserves the exact Skill Runtime v1 return shape for the invoked method.

### Error response format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method Not Found"
  },
  "id": "req-1"
}
```

Parse errors return `-32700` with `id: null`.

## Container Build

From `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge`:

```bash
docker build -f containers/nmap/Dockerfile -t openclaw-nmap-skill .
```

## Hardened Run Example

```bash
docker run -d -p 4000:4000 --cap-drop ALL --name nmap-skill \
  -e MCP_SKILL_TOKEN=secure_token_here \
  -e TOOL_NAME=nmap \
  -e SKILL_SLUG=nmap \
  openclaw-nmap-skill
```

## Local Test via curl

```bash
curl -sS http://127.0.0.1:4000/mcp \
  -H 'Authorization: Bearer secure_token_here' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "method": "health",
    "params": {},
    "id": "health-1"
  }'
```

## Isolation Warning

Do not run this container with:

- `--privileged`
- Docker socket mounts (for example: `-v /var/run/docker.sock:/var/run/docker.sock`)

## Notes

- This PoC introduces an MCP transport boundary only.
- Skill Runtime v1 method behavior and return contracts remain unchanged.
- No dynamic tool registry is included in this phase.
