# Cluster Coordination and Leader Election (Phase 15)

## Scope

Phase 15 adds deterministic cluster coordination for multi-supervisor operation:

1. leader election
2. shard ownership
3. shard-owner routing
4. cluster health/config consistency checks

This phase does not change:

1. local execution semantics outside shard-owner routing choice
2. lock ordering
3. queue behavior
4. circuit-breaker behavior
5. idempotency contract
6. federation HTTP contract

## Remaining Architectural Boundary (Phase 15)

Phase 15 intentionally does **not** provide partition containment. During a network partition:

1. each partition computes leader from its local membership view
2. each partition computes shard ownership from its local membership view
3. both partitions may continue serving requests

Deterministic routing is preserved *within* each partition, but containment across divergent membership views is not guaranteed in this phase.

This is expected and deliberate because consensus/quorum protocols are out of scope.

Next control-plane step after Phase 15:

1. partition safety guard
2. convergence delay window
3. majority-loss containment policy

## Files

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/leader-election.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/cluster-manager.js`
3. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`

## Cluster Config Contract

When `cluster.enabled === true`:

1. `federation.enabled` must be `true`
2. local `nodeId` must be provided via:
   1. `options.cluster.nodeId`, else
   2. `process.env.SUPERVISOR_NODE_ID`
3. identity contract is `peerId == nodeId`
4. all nodes must share identical:
   1. `shardCount`
   2. `leaderTimeoutMs`
   3. `heartbeatIntervalMs`

Mismatch handling:

1. startup strict mode: fail supervisor initialization on reachable healthy mismatch
2. runtime mode: mismatched peer is marked `DOWN` and excluded from cluster decisions
3. counter incremented: `cluster.config_mismatch`

## Single Heartbeat Owner

When cluster mode is enabled:

1. ClusterManager is the only heartbeat scheduler.
2. Supervisor does not start the normal federation heartbeat loop.
3. ClusterManager stops any existing federation heartbeat timer and owns periodic reconciliation.

This prevents dual heartbeat loops and conflicting health views.

## Leader Election

Election inputs:

1. healthy membership snapshot for the current tick
2. node IDs only (priority ignored in this phase)

Election rule:

1. leader is lexicographically smallest healthy `nodeId`

API:

1. `isLeader()`
2. `getCurrentLeader()`
3. `onLeadershipChange(callback)`

## Shard Ownership

Defaults:

1. `shardCount = 16`
2. `heartbeatIntervalMs = 5000`
3. `leaderTimeoutMs = 15000`

Rules:

1. `shardId = hash(slug) % shardCount`
2. owner selection uses rendezvous hashing over healthy, slug-capable nodes
3. only owner executes locally
4. non-owner forwards to owner through federation remote execution

## Immutable Membership Snapshot Rule

On each 5-second reconciliation tick:

1. ClusterManager runs one heartbeat reconciliation pass.
2. ClusterManager reads peer registry once.
3. ClusterManager validates peer config compatibility.
4. ClusterManager builds one immutable snapshot (`Object.freeze`).
5. The snapshot includes:
   1. `version`
   2. `createdAt`
   3. `healthyNodes`
   4. node capabilities
   5. config compatibility flags

Routing/election guarantees:

1. leader election uses only the current immutable snapshot
2. shard owner resolution uses only the current immutable snapshot
3. request routing uses a captured snapshot per request
4. no request-time dynamic registry reads are used for ownership decisions
5. next snapshot is adopted only on the next tick boundary

## Failover and Replay Safety

For owner timeout:

1. timed-out owner is marked `DOWN`
2. with `idempotencyKey`: retry is allowed by recomputing owner from the same captured snapshot minus failed/tried owners
3. without `idempotencyKey`: cross-peer retry is blocked

Replay handling:

1. remote `DUPLICATE_EXECUTION` replay success is returned directly
2. no local execution occurs after successful remote replay/success

## Rebalance Metric Semantics

`cluster.shard_rebalance` does not increment for:

1. initial startup baseline
2. initialization-only calculations
3. self-only membership snapshots

Increment occurs only when:

1. post-start membership transition changes shard assignment digest

## Metrics

Cluster metrics added:

1. `cluster.leader_elected`
2. `cluster.shard_rebalance`
3. `cluster.node_status`
4. `cluster.current_leader`
5. `cluster.config_mismatch`
6. `cluster.shard_count`
7. `cluster.leader_timeout_ms`
8. `cluster.heartbeat_interval_ms`

Cluster metrics must not include `request_id` labels.
