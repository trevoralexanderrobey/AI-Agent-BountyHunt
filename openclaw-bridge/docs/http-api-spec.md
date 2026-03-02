# HTTP API Spec (Phase 21 + Supervisor Hardening)

## Scope

This document defines the external HTTP ingress layer that wraps Supervisor v1 with Phase 21 governance controls and Supervisor structural hardening.

- Implementation files:
  - `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/http/server.js`
  - `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/http/handlers.js`
- Internal runtime semantics are unchanged.
- Supervisor, Spawner, MCP, and Runtime contracts are preserved.
- When `executionRouter` is configured, transport-level authorization checks are delegated to router policy.

## Configuration

`createHttpServer(options)` accepts:

```js
{
  httpServer: {
    enabled: false,      // default false
    port: 8080,          // default 8080
    host: "127.0.0.1"    // default 127.0.0.1
  },
  supervisorOptions: { ... }, // forwarded to createSupervisorV1 when supervisor not injected
  supervisor,                 // optional pre-created supervisor instance
  authEnabled: false,         // optional explicit auth expectation
  shutdownTimeoutMs: 30000,   // graceful drain timeout
  installSignalHandlers: true,
  exitOnSignal: true
}
```

HTTP ingress is optional: if `enabled=false`, `start()` returns success without binding a socket.

## Endpoints

### `POST /api/v1/execute`

Content-Type must be `application/json` (base media type match).

Request body:

```json
{
  "slug": "nmap",
  "method": "run",
  "params": {},
  "idempotencyKey": "optional",
  "retryPolicy": {
    "retries": 3,
    "delayMs": 1000,
    "backoffFactor": 2
  }
}
```

Validation rules:

1. `slug` non-empty string.
2. `method` non-empty string.
3. `params` object or `null`.
4. `idempotencyKey` length <= 128.
5. `retryPolicy.retries` integer `0..10`.
6. `retryPolicy.delayMs` number `>= 0`.
7. `retryPolicy.backoffFactor` number `>= 1`.

Header forwarding:

- `Authorization` forwarded to Supervisor request context as `authHeader`.
- `X-Request-Id` used if valid (`<=128`) or generated.
- `X-Principal-Id` forwarded as `principalId`.
- `X-API-Version` optional; defaults to `v1`.
- `X-Principal-Id` is mandatory only when router delegation is disabled; with `executionRouter` enabled, identity and authorization are decided centrally per request.

### API Hardening Requirements

1. Authentication required when auth is enabled and router delegation is disabled.
2. Identity required on execution when router delegation is disabled.
3. Deterministic request body size limit (`maxBodyBytes`).
4. Per-user burst quota and hourly quota enforced by centralized quota store.
5. Structured execution audit logs for auth, quota, execution, and egress decision points.
6. With router delegation enabled, tool policy enforcement is centralized in `src/core/execution-router.ts`.

Success response (`200`):

```json
{
  "ok": true,
  "data": {
    "result": {},
    "request_id": "uuid"
  },
  "api_version": "v1",
  "timestamp": "2026-02-25T00:00:00.000Z"
}
```

Error response:

```json
{
  "ok": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Human readable message",
    "request_id": "uuid"
  },
  "api_version": "v1",
  "timestamp": "2026-02-25T00:00:00.000Z"
}
```

Mapped status/code:

1. `400` -> `INVALID_REQUEST`
2. `401` -> `UNAUTHORIZED`, `UNAUTHENTICATED_EXECUTION`
3. `429` -> `RATE_LIMIT_EXCEEDED`, `EXECUTION_RATE_LIMIT_EXCEEDED`, `EXECUTION_QUOTA_EXCEEDED`
4. `503` -> `CIRCUIT_BREAKER_OPEN`, `NODE_CAPACITY_EXCEEDED`, `TOOL_CONCURRENCY_LIMIT_EXCEEDED`, `NODE_MEMORY_PRESSURE_EXCEEDED`, `NODE_CPU_SATURATION_EXCEEDED`, `EXECUTION_CONFIG_MISMATCH`
5. `500` -> `INTERNAL_ERROR`

### `GET /health`

`200` response:

```json
{
  "status": "healthy",
  "timestamp": "2026-02-25T00:00:00.000Z",
  "supervisor_ready": true,
  "queue_length": 0,
  "active_instances": 0,
  "node_id": "node-a",
  "scope": "node",
  "execution_config_hash": "sha256...",
  "execution_config_version": "v1",
  "expected_execution_config_version": "v1"
}
```

`503` response:

```json
{
  "status": "unhealthy",
  "reason": "string"
}
```

### `GET /metrics`

`200` response:

```json
{
  "metrics": {
    "counters": [],
    "histograms": [],
    "gauges": []
  },
  "timestamp": "2026-02-25T00:00:00.000Z"
}
```

The response format matches `supervisor.getMetrics()` and includes HTTP-layer metrics merged into the same schema.

## HTTP Metrics

Ingress updates:

1. `http.requests.total`
2. `http.requests.success`
3. `http.requests.error`
4. `http.request.duration_ms`
5. `http.errors_by_code`

Metrics are in-memory only and deterministic in snapshot format.

## Logging Contract

No direct console logging is used by the ingress layer.

Structured log hooks are emitted through injected logger methods:

1. request entry: method/route/request_id
2. response exit: status/duration/request_id
3. errors: code/message/request_id

## Graceful Shutdown

On `SIGINT` / `SIGTERM`:

1. ingress enters shutdown mode and rejects new requests with `503`.
2. waits for in-flight requests to complete (timeout: 30s default).
3. closes HTTP listener.
4. calls `supervisor.shutdown()`.
5. exits process with code `0` on success (`1` on failure).
