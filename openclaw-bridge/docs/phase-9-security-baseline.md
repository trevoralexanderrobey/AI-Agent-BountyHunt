# Phase 9 Security Baseline and Acceptance Checklist

## Scope

This document defines the Phase 9 security baseline for the current single-host distributed execution architecture:

- Runtime v1
- MCP skill server
- Spawner v2
- Supervisor v1
- In-memory Observability metrics

This is an implementation baseline and acceptance checklist. It does not introduce runtime behavior changes by itself.

## Section 1 — Asset Inventory

### 1.1 Control Plane Assets

| Asset | Sensitivity | Integrity Requirement | Availability Requirement |
|---|---|---|---|
| Supervisor in-memory state (instance pools, busy/ready status, pending spawns, reservations) | High | High | High |
| Supervisor private token map (container token references) | High | High | High |
| Spawner registry (container lifecycle state, metadata) | High | High | High |
| Spawner configuration constants (allowlist, resource/security flags) | High | High | Medium |
| Metrics in-memory state (counters/histograms/gauges) | Medium | Medium | Medium |

### 1.2 Execution Plane Assets

| Asset | Sensitivity | Integrity Requirement | Availability Requirement |
|---|---|---|---|
| Skill containers (`openclaw-*`) | High | High | High |
| MCP endpoint in each container (`/mcp`) | High | High | High |
| Skill Runtime v1 methods and responses | High | High | High |
| Job artifacts under `~/.openclaw/jobs/*` (`stdout.txt`, `stderr.txt`, `meta.json`, `semantic.json`, `anomalies.json`) | High | High | Medium |

### 1.3 Secrets

| Asset | Sensitivity | Integrity Requirement | Availability Requirement |
|---|---|---|---|
| `MCP_SKILL_TOKEN` per container | High | High | High |
| Any runtime env vars passed to containers | High | High | Medium |
| Supervisor/Spawner process memory containing tokens | High | High | High |

### 1.4 Host Boundary Assets

| Asset | Sensitivity | Integrity Requirement | Availability Requirement |
|---|---|---|---|
| Docker daemon control interface (root trust anchor) | High | High | High |
| Host filesystem paths used by bridge/spawner/runtime | High | High | High |
| Host network namespace and Docker bridge networks | High | High | High |

### 1.5 Observability Data Assets

| Asset | Sensitivity | Integrity Requirement | Availability Requirement |
|---|---|---|---|
| Supervisor metrics snapshots | Low | Medium | Medium |
| Spawner metrics snapshots | Low | Medium | Medium |
| Derived operational posture (capacity, failure rates, timeouts) | Medium | Medium | Medium |

## Section 2 — Trust Boundaries

### 2.1 Boundary Diagram

```text
Client
  |
  |  (Boundary 1)
  v
Supervisor v1
  |
  |  (Boundary 2)
  v
Spawner v2
  |
  |  (Boundary 3)
  v
Docker Engine (Host Privileged)
  |
  |  (Boundary 4)
  v
Skill Container (MCP + Runtime v1)

Metrics Boundary:
Supervisor/Spawner internal runtime state -> metrics snapshot surface
```

### 2.2 Boundary Requirements

| Boundary | Authentication Requirement | Authorization Model | Network Isolation Expectation |
|---|---|---|---|
| 1) Client → Supervisor | Required in Phase 9 (bearer or pluggable auth) | Caller allowed skill/method set; reject unknown principals | Supervisor endpoint not publicly exposed by default; explicit ingress only |
| 2) Supervisor → Spawner | Internal in-process/module trust | Supervisor-only invocation of spawner APIs | No external network dependency required |
| 3) Spawner → Docker | Host privileged boundary; local process identity must be trusted | Strict allowlist image policy; no arbitrary flags/env/volumes/privileged | Docker socket/CLI only from spawner host context |
| 4) Host → Container | Per-container token auth required at MCP | Method allowlist at MCP + runtime method-level validation | Dedicated Docker network, no host port publication required |
| 5) Metrics Boundary | Read access should be restricted to trusted operators/processes | Snapshot-only access, no mutation path exposed externally | No token/network address/container-id leakage in metrics |

## Section 3 — Required Phase 9 Controls

### 3.1 Supervisor Authentication Layer

Required implementation:

1. Add auth middleware/guard before `execute()` is callable from any external transport layer.
2. Support bearer token validation as minimum baseline.
3. Define pluggable auth interface (mTLS-ready abstraction), example contract:
   - `authenticate(requestContext) -> { ok, principalId, authType, error? }`
4. Auth enablement must be config-driven (on/off + provider selection).
5. No hardcoded credentials in source.
6. Auth failures return structured denied response; no internal secret disclosure.

Minimum config requirements:

- `SUPERVISOR_AUTH_ENABLED=true|false`
- `SUPERVISOR_AUTH_MODE=bearer|pluggable`
- Secret source via env or external secret provider adapter (not literal in code).

### 3.2 Per-Caller Rate Limiting

Required implementation:

1. Enforce at Supervisor ingress before slug lock acquisition.
2. Bucket key must be token-based principal ID, with IP fallback only when unauthenticated/internal.
3. O(1) in-memory token bucket or fixed-window counter with bounded state.
4. Configurable limits per time window.
5. Rejected requests must return structured rate-limit error.
6. Must not alter current lock model or introduce lock contention across slugs.

Minimum config requirements:

- `SUPERVISOR_RATE_LIMIT_ENABLED=true|false`
- `SUPERVISOR_RATE_LIMIT_RPS=<int>`
- `SUPERVISOR_RATE_LIMIT_BURST=<int>`

### 3.3 End-to-End `request_id` Propagation

Required implementation:

1. Generate `request_id` at `execute()` entry if caller does not provide one.
2. Propagate `request_id` to:
   - Spawner invocation context
   - MCP JSON-RPC request (`id` format or metadata envelope)
   - Metrics labels
   - Structured error responses
3. Preserve current result/error contracts except additive `request_id` fields where documented.
4. `request_id` must never include tokens or secret-derived material.
5. `request_id` format must be deterministic and collision-resistant for process scope.

### 3.4 Idempotency Key Contract

Required implementation:

1. Add optional `idempotencyKey` input to `execute()` context.
2. For idempotent replay window, duplicate key + same principal + same slug/method returns the original result payload.
3. Non-idempotent requests (no key) preserve existing behavior.
4. Maintain in-memory completed-request store with bounded TTL and max entries.
5. Define eviction policy:
   - TTL default (for example 5 minutes)
   - LRU or oldest-first bounded eviction when max entries exceeded
6. Idempotency cache must store result/error payloads only; no token material.

Minimum config requirements:

- `SUPERVISOR_IDEMPOTENCY_ENABLED=true|false`
- `SUPERVISOR_IDEMPOTENCY_TTL_MS=<int>`
- `SUPERVISOR_IDEMPOTENCY_MAX_ENTRIES=<int>`

### 3.5 Container Hardening Backlog (Execution Platform)

Required backlog items (tracked and owned):

1. Rootless Docker feasibility and migration plan.
2. Seccomp profile enforcement for skill containers.
3. AppArmor profile enforcement (Linux only).
4. Docker daemon hardening baseline:
   - least-privilege daemon access
   - audited daemon config
   - controlled group membership
5. CIS-aligned host/container baseline checks (documented controls list).
6. Host least-privilege policy for spawner runtime user/service account.

## Section 4 — Threat Mapping (STRIDE)

| Control | STRIDE Categories Mitigated | Residual Risk After Implementation |
|---|---|---|
| Supervisor Authentication Layer | Spoofing, Elevation of Privilege, Repudiation | Stolen valid credentials still usable until rotation/revocation |
| Per-Caller Rate Limiting | Denial of Service, Tampering (abusive high-rate calls) | Distributed low-rate attacks across many principals may still consume capacity |
| End-to-End `request_id` Propagation | Repudiation, Tampering (traceability), DoS triage | Requires operational discipline to use IDs in incident workflows |
| Idempotency Key Contract | Denial of Service (duplicate replay load), Tampering (repeat side effects) | Memory-backed store loss on process restart; bounded replay window only |
| Container Hardening Backlog | Elevation of Privilege, Information Disclosure, Tampering | Kernel/container runtime zero-days remain possible; risk reduced, not eliminated |

## Section 5 — Acceptance Checklist

### 5.1 Checklist JSON Shape

```json
{
  "auth_layer_added": false,
  "rate_limit_enforced": false,
  "request_id_propagation_verified": false,
  "idempotency_contract_enforced": false,
  "container_hardening_backlog_documented": false,
  "no_token_leakage_verified": false,
  "rate_limit_does_not_break_locking": false,
  "errors": []
}
```

### 5.2 Measurable Validation Criteria

1. `auth_layer_added`
   - Pass when unauthenticated call is rejected and authenticated call succeeds for allowed method.
   - Pass when auth can be toggled via config without code change.

2. `rate_limit_enforced`
   - Pass when requests above configured burst/window are rejected with structured limit error.
   - Pass when requests below limit continue to succeed.

3. `request_id_propagation_verified`
   - Pass when a single request shows same `request_id` in Supervisor trace, Spawner context, MCP call payload, metrics labels, and structured error/success response.

4. `idempotency_contract_enforced`
   - Pass when duplicate call with same `idempotencyKey` returns byte-equivalent prior result within TTL.
   - Pass when call without key executes normally (no behavior drift).

5. `container_hardening_backlog_documented`
   - Pass when all required backlog items in Section 3.5 are ticketed with owner and target milestone.

6. `no_token_leakage_verified`
   - Pass when metrics snapshot, structured errors, and status APIs contain no token/auth secret values.

7. `rate_limit_does_not_break_locking`
   - Pass when load test confirms no stuck BUSY state and no lock starvation regression under rate-limited and non-rate-limited traffic.

8. `errors`
   - Must be empty for acceptance.
   - Any non-empty entry blocks Phase 9 completion.

## Section 6 — Non-Interference Constraints

The following constraints are mandatory for Phase 9 implementation:

1. No changes to runtime execution semantics.
2. No change to MCP JSON-RPC contract behavior.
3. No change to Spawner/Supervisor lifecycle state machines.
4. No secret logging (tokens, auth headers, secret env values).
5. No new Docker control surface exposed to callers.
6. No observability drift that changes routing/lifecycle decisions.

## Section 7 — Rollout Plan

### Step 1: `request_id`

Implement first to establish traceability foundation.

Verification:

1. Single request path includes stable `request_id` in all required propagation points.
2. Error paths include same `request_id`.

### Step 2: Auth Layer

Implement Supervisor auth gate with config-driven enablement.

Verification:

1. Unauthorized requests denied.
2. Authorized requests succeed.
3. No hardcoded secret in repository.

### Step 3: Rate Limiting

Implement per-caller limiter before slug lock.

Verification:

1. Over-limit requests rejected.
2. Under-limit requests unaffected.
3. Lock behavior and throughput remain stable.

### Step 4: Idempotency

Implement optional idempotency key store and replay contract.

Verification:

1. Duplicate keyed requests replay prior result.
2. Non-keyed requests preserve baseline behavior.
3. TTL and eviction operate as configured.

### Step 5: Container Hardening Tasks

Execute backlog controls that do not alter runtime API contracts.

Verification:

1. Rootless/seccomp/AppArmor/daemon-hardening status tracked and validated per environment.
2. Security posture improvements documented without widening Docker surface.

## Phase 9A Implementation Notes

1. Authentication policy is env-first:
   - `SUPERVISOR_AUTH_TOKEN` is primary.
   - fallback `createSupervisorV1({ auth: { bearerToken } })` is allowed for local tests/harnesses.
2. Bearer token validation must use constant-time comparison:
   - token length guard first
   - `crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))`
3. Rate limiting is in-memory per-principal token bucket:
   - key: `principalId` or `"anonymous"`
   - O(1) check/update
   - no lock acquisition, no timers, no await
4. `request_id` propagation points in Phase 9A:
   - generated or accepted at `execute()` entry
   - forwarded as MCP JSON-RPC `id`
   - attached to supervisor-thrown errors (`request_id`, `details.request_id`)
   - passed as additive metadata to spawner calls
5. Spawner metadata pass-through is non-functional/additive:
   - `spawnSkill(slug, { requestId, principalId })`
   - `terminateSkill(containerId, { requestId, principalId })`
   - no spawner signature or behavior change required
6. Metrics cardinality guard:
   - `request_id` labels are applied only to failure/error counters
   - not applied to success counters, gauges, or latency histograms
7. Deferred from Phase 9A:
   - idempotency keys
   - queueing/retry orchestration

## Phase 9B Implementation Notes

1. Idempotency is optional and disabled by default:
   - enabled via `createSupervisorV1({ idempotency: { enabled: true } })`
   - default TTL: `300000` ms
   - default max entries: `1000`
2. `execute(slug, method, params, requestContext)` accepts optional:
   - `requestContext.idempotencyKey`
3. Replay eligibility requires all of:
   - same normalized principal ID
   - same slug
   - same method
   - same idempotency key
   - same stable JSON params hash
4. Idempotency lookup occurs after:
   - request ID derivation
   - auth validation
   - rate limit check
   and before slug-lock acquisition/capacity checks.
5. Replay path is non-executing:
   - no lock reservation
   - no capacity reservation
   - no spawn attempt
   - no MCP call
6. Store records only completed outcomes:
   - successful runtime results
   - runtime-style JSON-RPC error envelopes (`{ ok:false, error:{...} }`)
   - transport failures / `INSTANCE_FAILED` are never cached
7. Store schema is in-memory only:
   - key: `${principalId}::${slug}::${method}::${idempotencyKey}`
   - value: `{ createdAt, paramsHash, result, error }`
8. Safety constraints:
   - no tokens/container IDs/network addresses in idempotency store
   - no changes to lock scope
   - no queueing/retry semantics added

## Phase 9C Implementation Notes

1. Queueing/retry is optional and disabled by default:
   - enabled via `createSupervisorV1({ queue: { enabled: true, maxLength } })`
   - default queue max length: `100`
   - default queue poll interval: `250ms`
2. Queue implementation:
   - in-memory FIFO (`RequestQueue`) with O(1) enqueue/dequeue/peek
   - bounded length; full queue causes explicit capacity rejection
3. Retry policy is request-scoped and opt-in via:
   - `requestContext.retryPolicy = { retries, delayMs, backoffFactor }`
   - defaults when provided: `{ retries: 3, delayMs: 1000, backoffFactor: 2 }`
4. Retry eligibility:
   - only for non-idempotent methods (`run`, `tag_baseline`)
   - only on transport-level supervisor failure (`INSTANCE_FAILED`)
   - runtime-style error envelopes are not retried
5. Retry scheduling:
   - retries decremented before enqueue
   - next execution delayed by current `delayMs`
   - next retry uses exponential delay (`delayMs * backoffFactor`)
   - no infinite retry loop
6. Queue processing constraints:
   - oldest-first dispatch
   - capacity check before dispatch
   - no lock scope changes; processing reuses existing `execute()` flow
   - no spawner/MCP behavior changes
7. Observability additions (supervisor namespace):
   - `supervisor.queue.length` gauge
   - `supervisor.retries.count` counter
   - `supervisor.retry.failure` counter
   - `supervisor.capacity.rejection.due.to.queue` counter
   - `supervisor.queue.execution.delay.histogram` histogram
8. Security/non-interference:
   - no token logging
   - no new Docker surface
   - no lifecycle/state-machine drift

## Phase 9D Implementation Notes

1. Circuit breaker is optional and disabled by default.
   - Enable with `createSupervisorV1({ circuitBreaker: { enabled: true } })`
   - Defaults:
     - `failureThreshold: 5`
     - `successThreshold: 2`
     - `timeout: 30000`
2. Per-skill circuit state is maintained in memory:
   - `CLOSED`, `OPEN`, `HALF_OPEN`
   - fields: `failureCount`, `successCount`, `lastFailureAt`, `lastTransitionAt`
3. Pre-lock request gating:
   - breaker check occurs before slug lock acquisition
   - `OPEN` rejects immediately with `CIRCUIT_BREAKER_OPEN`
   - `HALF_OPEN` permits one in-flight request via lease; concurrent probe attempts are rejected
4. State transitions:
   - `CLOSED -> OPEN` on threshold consecutive transport failures
   - `OPEN -> HALF_OPEN` when timeout elapses
   - `HALF_OPEN -> CLOSED` on consecutive probe successes
   - `HALF_OPEN -> OPEN` on first transport failure
5. Health scoring:
   - `100` for `CLOSED`
   - `50` for `HALF_OPEN`
   - `0` for `OPEN`
6. Metrics:
   - `supervisor.circuit_breaker.state` gauge (`OPEN=0`, `HALF_OPEN=1`, `CLOSED=2`)
   - `supervisor.circuit_breaker.trips` counter
   - `supervisor.circuit_breaker.recoveries` counter
   - `supervisor.skill.health` gauge
   - state/health gauges and transition counters update on state transitions
7. Queue interaction:
   - queue dispatch reuses normal `execute()` path, so breaker gates queued work identically
   - when breaker is `OPEN`, retries are not re-enqueued from `INSTANCE_FAILED` path
8. Non-interference constraints preserved:
   - no runtime/mcp/spawner contract changes
   - no lock scope expansion
   - no lifecycle state-machine changes
   - no secret/token disclosure
