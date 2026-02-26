# Deployment Topology and Rolling Upgrade Safety (Phase 17)

## Scope

Phase 17 adds operational hardening for multi-node deployment without changing runtime execution semantics.

Added:

1. bootstrap validation and node publication metadata
2. rolling upgrade version compatibility guard
3. startup/runtime mismatch isolation
4. version-skew freeze policy for promotion/rebalance/leader transitions
5. critical config change restart-only policy
6. token and TLS rotation safety as operational policy contracts

Not changed:

1. shard hashing
2. leader election algorithm
3. partition containment logic
4. idempotency behavior
5. queue behavior
6. tool execution behavior
7. consensus/quorum model

## Files

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/deployment/bootstrap-manager.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/deployment/version-guard.js`
3. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`
4. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/cluster-manager.js`

## Bootstrap Discipline

On startup, nodes enforce:

1. `cluster.enabled=true` requires federation enabled
2. `cluster.enabled=true` requires explicit nodeId
3. `cluster.enabled=true` requires `shardCount`, `leaderTimeoutMs`, `heartbeatIntervalMs`
4. if HTTP is enabled, TLS config must be present and enabled

Node publication metadata:

1. `nodeId`
2. `softwareVersion`
3. `configHash`
4. `shardCount`
5. `leaderTimeoutMs`
6. `heartbeatIntervalMs`

Publication is exposed through `cluster.node_metadata` gauge labels.

## Version Compatibility Guard

Compatibility policy:

1. same MAJOR version required
2. MINOR skew must be `<= 1`

Mismatch behavior:

1. incompatible peer is marked `DOWN`
2. `cluster.version_mismatch` increments on mismatch transition
3. strict startup join fails for startup-fatal incompatibility (`major_mismatch`, `invalid_version`)

## Snapshot Rule for Compatibility Freeze

Compatibility freeze uses the same immutable per-tick `observedSnapshot` used by reconciliation.

Counts are derived only from `observedSnapshot.healthyNodes`:

1. `observedPopulation`
2. `compatiblePopulation`

Peers already marked `DOWN` are excluded from both counts.

Freeze condition:

1. `freezeActive = compatiblePopulation <= observedPopulation / 2`

## Freeze Semantics

While `freezeActive=true`:

1. no stable snapshot promotion
2. no shard rebalance evaluation
3. leader transitions are suppressed
4. routing/shard ownership remains pinned to the last promoted stable snapshot

This guarantees version skew cannot influence shard routing decisions until safe promotion conditions return.

## Config Change Safety

Critical cluster config is restart-only:

1. `shardCount`
2. `leaderTimeoutMs`
3. `heartbeatIntervalMs`

Dynamic changes to these values are rejected with restart-required error semantics.

## Token Rotation Safety (Operational Contract)

Policy requires:

1. dual-token grace window (`currentToken` + `previousToken`)
2. expiration of previous token after configured window
3. no restart requirement for token rotation policy

Phase 17 enforces policy contracts and publication; runtime auth module token acceptor changes are out of scope.

## TLS Rotation Safety (Operational Contract)

Policy requires:

1. hot-reload capable certificate/CA rotation workflow
2. invalid certificate blocks safe cluster participation
3. mTLS CA bundle reload support without full cluster semantic drift

Phase 17 enforces deployment policy contracts; runtime TLS reload engine changes are out of scope.

## Metrics

Added/used in Phase 17:

1. `cluster.version_mismatch` counter
2. `cluster.node_metadata` gauge labels
3. existing `cluster.config_mismatch` remains unchanged

No Phase 17 metric adds `request_id` labels.
