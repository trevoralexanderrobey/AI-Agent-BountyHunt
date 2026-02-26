# Phase 18: Multi-Node Cluster Simulation & Fault Injection Harness

## Scope

This phase adds a deterministic, in-process simulation harness for multi-node Supervisor clusters.

Created modules:

1. `simulation/cluster-simulator.js`
2. `simulation/fault-injector.js`

This phase does not modify production routing, leader election, shard hashing, partition detector, or supervisor execution logic.

## Core Design Rules

1. Simulator executes real production Supervisor + ClusterManager APIs.
2. Simulator does not bypass `clusterManager.getSnapshot()` and `clusterManager.resolveOwnerForSlug()` ownership/routing logic.
3. Network transport may be mocked, but control-plane logic is not mocked.
4. Harness collects all invariant failures (non fail-fast).

## Deterministic Time and Scheduling

1. Simulator uses a single injected deterministic clock.
2. All simulation time-based behavior is clock-driven.
3. Cluster tick scheduling is controlled by injected time advancement, not real wall-clock `setInterval`.
4. Retry/backoff and queue timing are validated against deterministic clock advancement.
5. Any wall-clock leakage is treated as an invariant failure.

## Transport and Security Discipline

1. Federation traffic is routed through the same handler path (`/api/v1/execute`, `/metrics`, `/health`) in simulation.
2. Auth headers are required and validated.
3. Request-signing verification path is executed when enabled.
4. Missing/invalid auth and invalid signatures produce production-equivalent failures.
5. TLS handshake simulation is intentionally out of scope for Phase 18 (policy-level coverage is Phase 17).

## Fault Injection Interface

`createFaultInjector(options)` supports:

1. `setNodeDown(nodeId, down)`
2. `setLatency(nodeId, latencyMs)`
3. `setTimeout(nodeId, enabled)`
4. `setStatusOverride(nodeId, statusCodeOrNull)`
5. `injectVersionSkew(nodeId, softwareVersion)`
6. `injectConfigMismatch(nodeId, partialConfig)`
7. `setPartition(nodesA, nodesB)` (symmetric)
8. `setDirectionalDrop(fromNodeId, toNodeId, enabled)` (asymmetric)
9. `clearPartition()`

## Simulator Interface

`createClusterSimulator(options)` exposes:

1. `startCluster(config)`
2. `stopCluster()`
3. `injectPartition(nodesA, nodesB)`
4. `resolvePartition()`
5. `simulateRollingUpgrade(nodeId, newVersion)`
6. `runMixedLoadScenario(options)`
7. `restartNode(nodeId, options)`
8. `runStressSuite(options)`
9. `advanceTime(ms)`
10. `advanceTicks(count)`
11. `getValidationReport()`

## Snapshot and Restart Invariants

Enforced invariants include:

1. `snapshot_consistency_preserved`
2. `snapshot_persistence_consistent_after_restart`
3. `no_spurious_leader_change_on_restart`
4. `partition_baseline_consistent_after_restart`

Explicit snapshot binding check:

1. Capture request-entry snapshot version.
2. Track all owner-resolution/retry snapshot versions for that request.
3. Fail if any version differs from captured version.

Restart baseline check:

1. During partition restart, partition baseline source must remain consistent with stable membership baseline semantics.

## Scenario Coverage

Stress suite covers:

1. 5-node random 2-node partition behavior.
2. 6-node equal split (3/3) containment.
3. Rolling upgrade node-by-node.
4. Mixed-version skew checks.
5. Queue pressure plus federation routing.
6. Mixed tool-heavy and skill-heavy load.
7. Rapid flapping behavior under controlled time.
8. Restart during partition.
9. Restart during freeze probe.
10. Restart during rolling upgrade.
11. Asymmetric one-way partition loss.

## Validation Output Contract

`getValidationReport()` returns:

```json
{
  "no_split_brain_under_partition": true,
  "no_duplicate_execution_detected": true,
  "freeze_behavior_correct": true,
  "rolling_upgrade_invariants_hold": true,
  "idempotency_consistent_across_nodes": true,
  "snapshot_consistency_preserved": true,
  "snapshot_persistence_consistent_after_restart": true,
  "no_spurious_leader_change_on_restart": true,
  "partition_baseline_consistent_after_restart": true,
  "retry_backoff_deterministic": true,
  "no_hidden_global_state": true,
  "no_deadlock_detected": true,
  "mixed_tool_skill_load_stable": true,
  "errors": []
}
```
