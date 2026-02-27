# Scaling Strategy (Phase 19)

## Scope

This strategy defines capacity planning and scaling controls for production deployment.

## Horizontal Scaling

### Add-node behavior

- Add node to cluster membership.
- Allow health and compatibility validation to complete.
- Permit promotion/rebalance only after convergence rules are satisfied.
- Observe for one full stabilization window before further topology changes.

### Capacity formula (planning baseline)

Use:

`required_nodes = ceil((peak_rps * avg_exec_ms) / (1000 * per_node_parallelism * target_utilization))`

Recommended default planning factors:

- `target_utilization = 0.65`
- `per_node_parallelism` based on runtime profile and CPU quota

### Max cluster size per region

- Recommended soft max: 24 core nodes per region.
- Beyond soft max: split into additional region-local clusters and route at LB/DNS tier.

## Vertical Scaling

### Tool-heavy profile

- CPU: prioritize high core count and sustained CPU bandwidth.
- Memory: high memory headroom for large process output and analysis state.
- Storage I/O: high throughput scratch volume.

### Skill-heavy profile

- CPU: moderate-high core count.
- Memory: lower than tool-heavy, but stable heap headroom required.
- Network: prioritize low latency and predictable inter-node RTT.

## Backpressure Strategy

### Queue saturation policy

- Trigger early warning at queue depth >= 70% of configured max.
- Trigger critical action at queue depth >= 90%.
- At critical threshold, prioritize shedding low-priority traffic and scale horizontally.

### Federation overflow policy

- Allow deterministic forwarding under normal ownership rules.
- During containment/freeze/partition conditions, respect routing pinning and do not force rebalance behavior.

### Circuit breaker tuning guidance

- Tune error thresholds based on peer error rate and latency distributions.
- Use conservative retry budgets under degraded network conditions.
- Validate breaker settings during staged load tests.

## Scaling Guardrails

- Avoid concurrent large membership and version changes.
- Scale in steps and validate metrics between steps.
- Keep expected node count explicit and synchronized with deployment manifests.
- Run preflight before each production scaling event.

## Scaling Runbook Checkpoints

Before scale-out:

- No active partition alarm.
- No persistent freeze condition.
- No unresolved version/config mismatch.

After scale-out:

- Node reaches healthy state.
- Compatibility checks remain stable.
- Rebalance behavior is within expected envelope.
- Queue depth and p95 latency improve as predicted.
