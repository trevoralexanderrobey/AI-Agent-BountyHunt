# Tool Adapter Framework (Phase 11A)

## Purpose

Phase 11A introduces a standardized adapter framework for direct CLI-style tool execution inside Supervisor routing, without changing Spawner, MCP server, or container lifecycle semantics.

Implemented files:

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapter-interface.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/base-adapter.js`
3. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/tool-registry.js`
4. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/tool-validator.js`

## Adapter Interface Contract

All adapters must expose:

1. `name: string`
2. `slug: string`
3. `description: string`
4. `execute(input) -> Promise<ToolExecutionResult>`
5. `validateInput(params) -> Promise<ValidationResult>`
6. `normalizeOutput(rawOutput) -> Promise<object>`
7. `getResourceLimits() -> { timeoutMs, memoryMb, maxOutputBytes }`

### Execution Input

```json
{
  "params": {},
  "timeout": 30000,
  "requestId": "uuid"
}
```

### Execution Result

```json
{
  "ok": true,
  "result": {},
  "metadata": {
    "executionTimeMs": 12,
    "outputBytes": 128,
    "requestId": "uuid"
  }
}
```

### Validation Result

```json
{
  "valid": true,
  "errors": []
}
```

## BaseToolAdapter

`BaseToolAdapter` provides shared behavior:

1. input validation flow orchestration
2. timeout wrapping
3. error normalization (`TOOL_EXECUTION_ERROR` fallback)
4. metadata tracking (`executionTimeMs`, `outputBytes`, `requestId`)
5. output size enforcement against `maxOutputBytes`

Subclass responsibilities:

1. `executeImpl(input)`
2. `validateInput(params)`
3. `normalizeOutput(rawOutput)`
4. optional `getResourceLimits()`

## Registry Pattern

`createToolRegistry(config)` enforces allowlist-only execution:

1. `register(slug, adapter, { enabled })`
2. `get(slug) -> adapter | null`
3. `has(slug) -> boolean`
4. `list() -> [{ slug, name, enabled }]`
5. `seal()` to disallow further mutation

Rules:

1. slug format: lowercase alphanumeric + dashes
2. duplicate slug registration is rejected
3. adapter contract validation is required
4. disabled tools return `null` on lookup

## Validator Pattern

`createToolValidator(registry)` validates execution requests:

1. registered + enabled slug required
2. params must be a non-circular object
3. params size must be `< 1MB`
4. adapter `validateInput()` must pass

Result shape:

```json
{
  "valid": false,
  "errors": ["..."],
  "adapter": null
}
```

## Supervisor Routing Integration

Routing order in `execute()`:

1. auth and rate limit
2. idempotency replay check
3. if slug matches a registered tool adapter:
   - validate request via tool validator
   - execute adapter directly
   - bypass spawner, queue, circuit breaker, and skill instance capacity
4. otherwise continue normal skill-container path

This keeps existing skill runtime behavior unchanged while enabling explicit tool adapters.

## Error Conventions

Primary codes used by tool adapter flow:

1. `INVALID_TOOL_REQUEST`
2. `INVALID_TOOL_INPUT`
3. `TOOL_EXECUTION_ERROR`
4. `TOOL_OUTPUT_TOO_LARGE`

Tool adapter failures return runtime-style tool result envelopes (`ok: false`) from adapter execution path.

## Resource Limits

Default limits from `BaseToolAdapter`:

1. `timeoutMs: 30000`
2. `memoryMb: 512` (declarative limit for adapter policy)
3. `maxOutputBytes: 10485760`

Adapters may tighten these values via `getResourceLimits()`.

## Observability

Tool execution metrics emitted by Supervisor:

1. `tool.executions.total`
2. `tool.executions.success`
3. `tool.executions.error`
4. `tool.execution.duration_ms`
5. `tool.output_size_bytes`

These metrics are per-slug and integrate with existing in-memory metrics snapshots.
