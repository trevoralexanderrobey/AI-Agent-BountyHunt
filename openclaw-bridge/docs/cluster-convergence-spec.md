# Cluster Partition Containment and Convergence (Phase 16)

## Scope

Phase 16 adds partition containment and membership convergence guards without introducing consensus protocols.

Added capabilities:

1. partition detection
2. strict-majority loss guard
3. convergence stabilization window
4. snapshot promotion safety gates
5. forwarding backpressure during partition
6. shard/leader freeze while partitioned

## Non-Goals

This phase does not change:

1. leader election algorithm
2. shard hashing / rendezvous scoring
3. idempotency semantics
4. queue behavior
5. tool execution behavior
6. HTTP or peer-registry contracts
7. introduction of quorum voting, Raft, or consensus replication

## Files

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/partition-detector.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/cluster/cluster-manager.js`

## Majority and Partition Rules

Strict majority definition:

1. majority means `observedSize > previousStableSize / 2`

Partition entry rule:

1. enter partition when `observedSize <= previousStableSize / 2`

Equal-split containment:

1. with stable size `6`, observed size `3` is partitioned
2. this prevents dual-majority illusion in non-consensus mode

## Baseline Rule

`partitionEntryBaselineSize` must be derived from:

1. `last promoted stableSnapshot.healthyNodes.size`

It must not use:

1. observed snapshot size
2. raw peer-registry size
3. static initial configured size

This keeps partition detection/recovery symmetric with authoritative routing membership.

## Snapshot Model

Cluster manager maintains:

1. `observedSnapshot`: latest tick membership view
2. `stableSnapshot`: authoritative snapshot for routing/leader/shard ownership
3. `publishedSnapshot`: stable snapshot plus additive partition/convergence metadata

Only `stableSnapshot` is authoritative for:

1. leader state application
2. shard ownership resolution during containment
3. partition baseline semantics
4. routing snapshot returned to supervisor

## Convergence Stabilization Window

Option:

1. `convergenceWindowMs` default `10000`

Promotion conditions for `observedSnapshot -> stableSnapshot`:

1. not partitioned
2. observed membership differs from stable membership
3. convergence window elapsed since candidate membership first observed
4. same observed membership key seen for at least 2 consecutive ticks

If these are not met, promotion is delayed and stable snapshot remains unchanged.

## Partitioned State Behavior

While partitioned:

1. no stable snapshot promotion
2. no shard rebalance evaluation/increment
3. forwarding to remote peers disabled
4. cluster serves only shards owned in last stable snapshot
5. leader election computation is based on `stableSnapshot` only
6. leadership transitions are suppressed (effective leader pinned to stable state)
7. `observedSnapshot` is never used to apply leader transitions

## Recovery Rule

Recovery policy is stable-membership-only:

1. observed size must meet threshold `>= ceil(partitionEntryBaselineSize / 2)`
2. observed recovered membership key must remain identical for 2 consecutive ticks
3. on success, partition state clears and normal promotion logic resumes

## Forwarding Backpressure

During partition:

1. remote peer lookup returns `null` for non-local nodes
2. this disables cross-peer forwarding in existing supervisor flow
3. local shard ownership remains serviceable from stable snapshot

No supervisor code changes are required for the backpressure mechanism.

## Metrics

Counters:

1. `cluster.partition_detected`
2. `cluster.partition_recovered`

Gauges:

1. `cluster.partition_state` (`0` healthy, `1` partitioned)
2. `cluster.convergence_delay_active` (`0` inactive, `1` promotion delayed by convergence gates)

No `request_id` labels are used for these metrics.

## Failure-Mode Table

1. Minority side partition (6 -> 2):
   1. enters partition
   2. forwarding disabled
   3. shard/leader promotion frozen
2. Majority side continuity (6 -> 4):
   1. does not partition
   2. can continue convergence checks/promotions
3. Equal split (6 -> 3):
   1. partitioned due `<=` rule
   2. both sides freeze promotions
4. Transient flap:
   1. convergence delay prevents immediate rebalance
   2. requires two stable observed ticks
5. Recovery:
   1. threshold restored
   2. recovered membership stable for two ticks
   3. partition clears and promotion can resume
