# Federation Transport Foundation (Phase 12A)

## Scope

Phase 12A adds federation primitives only:

1. Peer registry
2. Remote execution client
3. Peer heartbeat monitoring
4. Federation mode flag in supervisor options

Routing and execution behavior are intentionally unchanged in this phase.

## Non-Goals

1. No modification to supervisor execution flow.
2. No capacity, queue, idempotency, circuit breaker, or lock model changes.
3. No remote routing decision logic.

## Peer Registry

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/peer-registry.js`

### Data Model

`Map<peerId, entry>` where `entry` is:

```json
{
  "url": "https://peer-a.example",
  "authToken": "<secret>",
  "status": "UP|DOWN",
  "capabilities": ["nmap", "ffuf"],
  "lastLatencyMs": 0,
  "lastHeartbeat": 0
}
```

### API

1. `registerPeer(peerId, config)`
2. `removePeer(peerId)`
3. `listPeers()`
4. `getHealthyPeersForSlug(slug)`

Additional internal helper:

1. `updatePeerHealth(peerId, health)`

### Behavior

1. `peerId` must be non-empty string.
2. `url` must be valid `http` or `https`.
3. `authToken` required for remote auth.
4. `capabilities` are normalized and de-duplicated.
5. `listPeers()` excludes `authToken`.
6. `getHealthyPeersForSlug(slug)` returns only `UP` peers supporting the slug.

## Remote Execution Client

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/remote-client.js`

### API

1. `createRemoteExecutionClient(options)`
2. `executeRemote(peer, payload)`

### Transport Contract

1. Endpoint: `POST /api/v1/execute` on remote Phase 10 API.
2. Forwards payload fields:
   1. `slug`
   2. `method`
   3. `params`
   4. `idempotencyKey`
   5. `retryPolicy`
   6. `request_id`
3. Headers:
   1. `Content-Type: application/json`
   2. `Authorization: Bearer <peer.authToken>`
   3. `X-Request-Id` when available
4. Timeout: `30000ms` default.
5. No internal retries.

### Return Shape

Success:

```json
{
  "ok": true,
  "peerId": "peer-a",
  "statusCode": 200,
  "latencyMs": 42,
  "response": { "ok": true, "data": {} }
}
```

Failure:

```json
{
  "ok": false,
  "error": {
    "code": "REMOTE_TRANSPORT_ERROR|REMOTE_INVALID_RESPONSE|REMOTE_ERROR|INVALID_PEER",
    "message": "...",
    "details": {}
  }
}
```

## Heartbeat Monitoring

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/federation/heartbeat.js`

### API

1. `createPeerHeartbeat({ peerRegistry, intervalMs, timeoutMs })`
2. `start()`
3. `stop()`
4. `runOnce()`
5. `isRunning()`

### Behavior

1. Poll cadence: 60s default.
2. Probe endpoint: `GET /health`.
3. Updates peer fields:
   1. `status` (`UP` or `DOWN`)
   2. `lastLatencyMs`
   3. `lastHeartbeat`
4. Monitoring is non-blocking and isolated from supervisor routing.

## Supervisor Federation Flag

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`

### Option

```json
{
  "federation": {
    "enabled": false
  }
}
```

### Behavior

1. Default is disabled.
2. Phase 12A only parses the flag.
3. No routing/execution behavior change.

## Security Notes

1. Peer authentication uses per-peer bearer tokens.
2. No token is exposed in peer list output.
3. No retries are performed by remote client (prevents hidden replay behavior).
4. Federation primitives do not mutate local execution state.

## Deterministic Federation Routing (Phase 12B)

Phase 12B enables capacity-overflow delegation with strict routing order and non-interference guarantees.

### Execute Ordering

For skill execution (`slug` in `SKILL_CONFIG`), routing order is:

1. `request_id` generation
2. auth validation
3. rate limiting
4. idempotency replay check
5. circuit breaker gate check
6. federation decision
7. local execution path

Federation does not run for tool adapters (`toolRegistry` path), idempotent replay hits, or queue retry executions.

### Federation Trigger Conditions

Federation is considered only when all are true:

1. `federation.enabled === true`
2. slug is a skill (not a direct tool adapter)
3. local capacity snapshot is exhausted: `instances.size + pendingSpawns >= maxInstances`
4. circuit is effectively closed for this request (`HALF_OPEN` lease requests are excluded)
5. at least one healthy peer supports the slug

### Deterministic Peer Selection

1. Candidate peers come from `peerRegistry.getHealthyPeersForSlug(slug)` (already sorted by latency then `peerId`).
2. Supervisor attempts peers in that deterministic order.
3. No randomization, no round-robin, no speculative fan-out.

### Failover and Timeout Safety

1. `429` / `503` responses trigger failover to the next healthy peer.
2. Transport timeout marks the peer `DOWN` and increments `supervisor.federation.peer_down`.
3. Timeout with **no** `idempotencyKey` stops failover and returns `SUPERVISOR_CAPACITY_EXCEEDED` to prevent duplicate execution risk.
4. Timeout with `idempotencyKey` allows failover to next peer (replay-safe).
5. If all peers fail, supervisor returns existing `SUPERVISOR_CAPACITY_EXCEEDED`.

### Remote Metrics Isolation

Remote delegation only emits federation namespace metrics:

1. `supervisor.federation.attempt`
2. `supervisor.federation.success`
3. `supervisor.federation.failure`
4. `supervisor.federation.latency_ms`
5. `supervisor.federation.peer_down`

Remote path does not increment local execution counters, tool counters, instance counters, or spawn metrics.

### Non-Interference Guarantees

1. No new `await` inside slug lock.
2. Federation decision occurs before local lock acquisition.
3. No local pool mutation on remote success/failure.
4. No queue mutation for federation attempts.
5. No circuit breaker state mutation caused by federation transport outcomes.
6. No dual execution: remote success returns immediately and skips local execution.
