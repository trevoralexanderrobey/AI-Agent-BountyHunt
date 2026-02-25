# Batch 1 Tools (Phase 11B)

## Overview

Phase 11B adds three lightweight CLI tool adapters built on the Phase 11A framework:

1. `curl`
2. `nslookup`
3. `whois`

All tools execute with `spawn()` argument arrays (`shell: false`) and enforce validation, timeout, and output limits.

## curl Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/curl-adapter.js`

### Input

```json
{
  "url": "https://example.com/api",
  "method": "GET",
  "headers": { "Accept": "application/json" },
  "body": "optional string",
  "timeout": 5000
}
```

### Validation Rules

1. `url` required, must be valid `http` or `https` URL.
2. `method` optional: `GET|POST|PUT|DELETE|HEAD`.
3. `headers` optional object, reserved header names are rejected:
   - `Authorization`
   - `Cookie`
   - `Set-Cookie`
   - `X-API-Key`
   - `Proxy-Authorization`
4. `body` only allowed for `POST`/`PUT`.
5. `timeout` optional, must be `<= 30000` ms.

### Output

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "...",
  "size_bytes": 1234
}
```

### Resource Limits

1. timeout: `30000ms`
2. memory: `256MB`
3. max output: `5MB`

### Security Notes

1. No shell interpolation.
2. Headers are validated and filtered for reserved names.
3. Output capture is bounded.

## nslookup Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/nslookup-adapter.js`

### Input

```json
{
  "domain": "example.com",
  "recordType": "A",
  "server": "8.8.8.8"
}
```

### Supported Record Types

1. `A`
2. `AAAA`
3. `MX`
4. `NS`
5. `TXT`
6. `SOA`

### Validation Rules

1. `domain` required and must be valid hostname/domain format.
2. `recordType` optional, defaults to `A`.
3. `server` optional, must be valid IP address when provided.

### Output

```json
{
  "domain": "example.com",
  "record_type": "A",
  "answers": [
    { "type": "A", "value": "93.184.216.34" }
  ]
}
```

### Resource Limits

1. timeout: `10000ms`
2. memory: `128MB`
3. max output: `1MB`

### Timeout Behavior

`nslookup` process is force-killed on timeout and returns structured tool execution error.

## whois Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/whois-adapter.js`

### Input

```json
{
  "query": "example.com",
  "server": "whois.verisign-grs.com"
}
```

`query` can be a domain or IP.

### Validation Rules

1. `query` required, must be valid domain or IP.
2. `server` optional, must be valid hostname when provided.

### Output

```json
{
  "query": "example.com",
  "registrar": "...",
  "created": "...",
  "expires": "...",
  "nameservers": ["a.iana-servers.net"],
  "raw": "..."
}
```

`raw` is truncated to `10000` characters.

### Resource Limits

1. timeout: `15000ms`
2. memory: `256MB`
3. max output: `2MB`

### Privacy Considerations

WHOIS output can include registrant-related fields depending on registry policy. Use minimum necessary retention for downstream consumers.

## Registration

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/index.js`

`registerBatch1Tools(toolRegistry)` registers all three adapters:

1. `curl`
2. `nslookup`
3. `whois`

Supervisor calls this at tool registry initialization.

## Error Codes

Primary tool-path codes:

1. `INVALID_TOOL_REQUEST`
2. `INVALID_TOOL_INPUT`
3. `TOOL_EXECUTION_ERROR`
4. `TOOL_OUTPUT_TOO_LARGE`

## Observability

Tool execution emits:

1. `tool.executions.total`
2. `tool.executions.success`
3. `tool.executions.error`
4. `tool.execution.duration_ms`
5. `tool.output_size_bytes`
