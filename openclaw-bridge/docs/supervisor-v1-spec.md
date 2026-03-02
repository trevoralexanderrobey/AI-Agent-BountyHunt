# Supervisor v1 Spec

## Scope

Supervisor v1 is a deterministic routing and pooling layer over Spawner v2.

- Uses `createSpawnerV2()` for all instance lifecycle operations.
- Never runs Docker commands directly.
- Never changes MCP/runtime payload contracts.
- Never exposes container tokens.

Execution router relationship:

- `src/core/execution-router.ts` is the canonical policy enforcement point for external execution paths.
- Supervisor v1 remains the runtime execution backend for slug/method dispatch where legacy/runtime flows are delegated.
- Transport layers should apply parsing/serialization only and delegate authorization/tool policy decisions to the execution router when enabled.

Module path:

- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`

## Public API

`createSupervisorV1(options = {})` returns:

1. `initialize()`
2. `execute(slug, method, params)`
3. `getStatus()`
4. `reapIdle()`
5. `shutdown()`

## Configuration

Static per-skill config:

```js
const SKILL_CONFIG = {
  nmap: {
    maxInstances: 5,
    idleTTLms: 60000,
  },
};
```

Allowed methods are the MCP Runtime v1 intersection:

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

## State Model

Pool state per slug:

`Map<slug, { instances: Map<containerId, { state: "READY" | "BUSY", lastUsedAt: number }> }>`

Private internal maps:

1. `instanceMetaById`: `{ slug, name, networkAddress }`
2. `instanceTokenById`: `token`
3. `pendingSpawnsBySlug`: pending spawn reservations
4. `reapReservationsBySlug`: idle-reap reservation set
5. `slugLocks`: per-slug mutexes
6. `isShuttingDown`: shutdown gate

Token handling:

- Token is only used for MCP authorization during routing.
- Token never appears in `getStatus()` or returned errors.

## Locking Model

Per-slug lock protects only:

1. READY instance selection
2. Capacity check / spawn reservation
3. BUSY assignment
4. Pool metadata mutation
5. Reap eligibility re-check/reservation

The lock is never held across:

1. `spawner.spawnSkill`
2. MCP HTTP request/response
3. `spawner.terminateSkill`

This preserves concurrency and deterministic behavior.

## Method Behavior

### initialize()

1. Calls `spawner.initialize()`.
2. Does not pre-spawn any containers.
3. Returns `{ ok: true, initialized: true }`.

### execute(slug, method, params)

1. Rejects if shutdown started: `SUPERVISOR_SHUTTING_DOWN`.
2. Validates slug and method.
3. Under lock:
   1. Re-checks shutdown gate.
   2. Selects deterministic READY instance (oldest `lastUsedAt`, then `containerId`).
   3. If no READY, reserves spawn if under maxInstances.
   4. If at capacity, throws `SUPERVISOR_CAPACITY_EXCEEDED`.
4. Spawns outside lock if reserved.
5. On spawn success, registers instance and marks BUSY under lock.
6. Sends JSON-RPC to instance `networkAddress` with bearer token.
7. Response classification:
   1. Transport/HTTP/timeout/malformed JSON -> instance failure path.
   2. Valid JSON-RPC `result` -> return result unchanged.
   3. Valid JSON-RPC `error` envelope -> return runtime-style `{ ok:false, error }`, keep instance READY.
8. On success/runtime-style error, marks instance READY and updates `lastUsedAt`.
9. On transport failure:
   1. Removes instance from pool/private maps under lock.
   2. Terminates via spawner outside lock.
   3. Throws `INSTANCE_FAILED`.

Invariant:

- BUSY entries are never left stuck after timeout/transport failure.

### reapIdle()

1. Under lock, for each slug, reserves READY instances older than `idleTTLms`.
2. No state mutation during reservation.
3. Terminates reserved candidates outside lock.
4. Re-enters lock:
   1. Clears reservation.
   2. On termination success, removes instance from pool/private maps.
   3. On termination failure, keeps instance unchanged.
5. Never reaps BUSY instances.
6. Returns `{ ok: true, reaped, failed }`.

### getStatus()

Returns deterministic sanitized snapshot:

```json
{
  "ok": true,
  "isShuttingDown": false,
  "skills": [
    {
      "slug": "nmap",
      "maxInstances": 5,
      "idleTTLms": 60000,
      "counts": { "ready": 0, "busy": 0, "total": 0 },
      "instances": []
    }
  ]
}
```

No token or secret fields are exposed.

### shutdown()

1. Sets `isShuttingDown = true`.
2. Under lock, snapshots and detaches all instances from supervisor state.
3. Terminates all snapshotted instances outside lock.
4. Clears all maps and locks.
5. Returns:

```json
{
  "ok": true,
  "terminated": 0,
  "failed": 0,
  "errors": []
}
```

New execute calls are rejected immediately after shutdown starts.

## Error Codes

Supervisor structured errors:

1. `INVALID_SLUG`
2. `INVALID_METHOD`
3. `SUPERVISOR_CAPACITY_EXCEEDED`
4. `SPAWN_FAILED`
5. `INSTANCE_FAILED`
6. `SUPERVISOR_SHUTTING_DOWN`

## Determinism Guarantees

1. Selection order is stable: `lastUsedAt`, then `containerId`.
2. No queueing behavior; capacity pressure fails immediately.
3. Per-instance single in-flight execution is enforced by BUSY state assignment under lock.
4. Reaping uses reservations to avoid execute/reap races.

## Security Constraints

1. Supervisor never executes Docker commands.
2. Supervisor never returns token/auth data.
3. Supervisor sends MCP auth token only in request header to target instance.
4. Supervisor does not modify container environment or spawn flags.
