# Persistent Control Plane State (Phase 14)

## Scope

Phase 14 adds local file-backed persistence for supervisor control-plane metadata to survive process restarts.

This phase does not change:

1. execution semantics
2. lock ordering
3. runtime contracts
4. federation routing safety rules
5. queue/circuit/idempotency decision ordering

## Files

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/state/persistent-store.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/state/state-manager.js`
3. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`
4. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/request-queue.js`
5. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/circuit-breaker.js`
6. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/peer-registry.js`

## Persistent Store

### Path Resolution

State file path resolves as:

1. `process.env.STATE_STORE_PATH` if set and non-empty
2. default `./data/control-plane-state.json`

### Format

Envelope:

```json
{
  "version": 1,
  "persistedAt": 0,
  "reason": "string",
  "payload": {}
}
```

### Guarantees

1. Atomic writes use temp file + `rename`.
2. Writes are debounced (max once per second).
3. Missing file is treated as empty state.
4. Corrupted JSON is handled gracefully (load failure is non-fatal).
5. Version mismatch is ignored without mutating runtime behavior.

## Persisted Structures

The payload persists:

1. `idempotencyStore`
2. `requestQueue`
3. `circuitBreakerState`
4. `peerRegistryMetadata` (no tokens)

### Sensitive Data Exclusions

Never persisted:

1. bearer tokens (`Authorization` / `authHeader`)
2. peer auth tokens
3. request signing secrets
4. TLS keys/cert private material
5. other runtime secret material

## Recovery Semantics

On supervisor startup:

1. load persisted envelope if present and version-compatible
2. restore idempotency entries
3. prune expired idempotency entries using current TTL
4. restore queued retry entries
5. drop expired queue entries
6. drop incomplete/in-flight queue entries
7. restore circuit breaker state
8. coerce `HALF_OPEN` to `OPEN`
9. restore peer metadata (tokenless)
10. trigger immediate heartbeat `runOnce()` before steady heartbeat loop
11. do not auto-retry incomplete executions

## Queue and Circuit Serialization Contracts

### Queue

`RequestQueue` adds:

1. `toArray()`
2. `fromArray(items)`

Supervisor stores only safe request-context fields for retries:

1. `requestId`
2. `principalId`
3. `idempotencyKey`
4. `retryPolicy`
5. `__queueRetryExecution`

### Circuit Breaker

`createCircuitBreaker()` adds:

1. `exportState()`
2. `importState(entries, { resetHalfOpenToOpen })`

## Peer Registry Serialization Contract

`createPeerRegistry()` adds:

1. `exportMetadata()`
2. `importMetadata(entries)`

`exportMetadata()` excludes `authToken`.

`importMetadata()` behavior:

1. updates existing peers with non-secret metadata
2. allows tokenless placeholder entries but keeps them `DOWN`
3. prevents `UP` status on peers with no auth token

## Persistence Triggers

State snapshots are scheduled after control-plane mutations, including:

1. idempotency writes/prunes/expiry deletes
2. queue enqueue/dequeue
3. circuit success/failure/transition updates
4. peer registry metadata updates
5. startup recovery cleanup pass

## Shutdown Behavior

1. no new persistence snapshots are scheduled during shutdown teardown
2. pending debounced writes are flushed before shutdown returns
3. this prevents accidental persistence of teardown-cleared runtime maps
