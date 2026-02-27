# Operational Playbook (Phase 19)

## Purpose

Operational procedures for deploying, upgrading, monitoring, and recovering the distributed execution fabric.

This playbook does not change runtime control-plane behavior.

## Production Mode Detection (Tooling Contract)

Deployment tooling treats production mode as enabled when any of the following is true:

- CLI flag `--env production`
- Explicit option `options.env === "production"`
- Environment `NODE_ENV=production`

Resolution precedence when conflicting values are provided:

- `--env` > `options.env` > `NODE_ENV`

## Day-0 Bootstrap Checklist

- Validate node identity and cluster/federation settings.
- Validate expected topology node count for production.
- Validate version compatibility targets for rollout window.
- Validate TLS certs and mTLS trust chain.
- Validate state path isolation per node.
- Validate debug flags are disabled in production.
- Confirm metrics endpoint is reachable.

## Day-1 Operations Checklist

- Confirm cluster health and partition state.
- Confirm freeze/convergence state.
- Confirm version/config mismatch counters are stable.
- Confirm queue depth and circuit-breaker status are within envelope.
- Confirm token and cert rotation windows are not approaching expiration.

## Rolling Upgrade Procedure

1. Select one node for upgrade.
2. Drain external ingress to that node (if applicable).
3. Upgrade node and restart with validated config.
4. Confirm node rejoins healthy and compatibility checks pass.
5. Confirm no unexpected partition/freeze condition.
6. Confirm rebalance behavior is within expected bounds.
7. Repeat for next node.

### Mandatory gates before next node

- Compatibility majority maintained.
- No active partition condition.
- Freeze not unexpectedly persistent.
- No anomalous rebalance spikes.

### Abort conditions

- Freeze persists unexpectedly.
- Partition detected during upgrade window.
- Version mismatch persists after expected convergence window.
- Config mismatch appears for upgraded node.

### Rollback choreography

1. Stop rollout.
2. Revert offending node to last known good artifact/config.
3. Confirm compatibility and containment metrics return to expected state.
4. Resume rollout only after gate checks pass.

## Incident Response Priority Order

1. Partition or containment alarms.
2. Compatibility/config mismatch alarms.
3. Queue saturation and federation overflow.
4. Latency and error-budget burn.

## Operational Drift Detection

### Detect unexpected freeze state

Track:

- `cluster.convergence_delay_active`
- `cluster.version_mismatch`
- `cluster.config_mismatch`
- `cluster.shard_rebalance`

Drift indicators:

- Convergence delay remains active beyond expected convergence window.
- Version/config mismatch counters continue increasing after remediation.
- Rebalance increments while freeze is expected to pin ownership.

### Detect unexpected partition state

Track:

- `cluster.partition_state`
- `cluster.partition_detected`
- `cluster.partition_recovered`

Drift indicators:

- Partition state remains `1` for longer than incident threshold.
- Repeated partition detect/recover oscillation (flapping).

### What to do if freeze persists unexpectedly

1. Confirm version skew inputs and deployment targets are correct.
2. Confirm no unresolved config mismatches.
3. Confirm membership is stable (heartbeat and peer health).
4. Pause upgrades and scale operations.
5. Apply rollback if mismatch cannot be resolved quickly.
6. Re-validate preflight and redeploy in controlled steps.

### Metrics that confirm convergence gates

- `cluster.convergence_delay_active == 0`
- `cluster.partition_state == 0`
- `cluster.version_mismatch` not increasing
- `cluster.config_mismatch` not increasing
- `cluster.shard_rebalance` stable after expected transition window

## Version Target Operations Notes

- `deployment.versionTargets` is an explicit list of planned peer versions for the rollout window.
- Preflight validates local version against each target version.
- Preflight does not guarantee all targets are mutually compatible.
- Operators must sequence rollout order to respect compatibility windows.

## Change Management Policy

- Critical cluster settings (`shardCount`, heartbeat timeout settings) require coordinated restart policy.
- Non-critical changes may use dynamic reload if supported.
- Any change affecting security posture requires preflight rerun and documented approval.

## Post-change Validation

- Run preflight validator.
- Run deploy-check summary.
- Validate dashboards and alert silence windows.
- Record rollout metadata: operator, artifact version, node order, incidents.
