# Observability Spec (Phase 21)

## Scope

Phase 21 standardizes execution-plane observability for multi-node governance.

1. Metrics remain deterministic and in-memory.
2. Threshold evaluation scope is explicit and node-local in this phase.
3. No control-plane routing semantics are changed by telemetry.

## Required Phase 21 Metrics

Every node must emit:

1. `tool.container.duration`
2. `tool.container.memory_usage`
3. `tool.container.cpu_usage`
4. `tool.execution.rejected`
5. `circuit.open`
6. `orphan.cleanup`
7. `container.orphan.cleaned`
8. `secret.access`

Additional egress observability:

1. `tool.container.egress.external_event`
2. `tool.container.egress.anomaly`

## Rejection Metric Contract

`tool.execution.rejected` labels must include:

1. `reason`
2. `node_id`
3. `tool`
4. `principal_hash`

## Alert Threshold Configuration

`observability.alertThresholds`:

1. `circuitOpenRate`
2. `executionRejectRate`
3. `memoryPressureRate`

`observability.thresholdScope` must be `node` in Phase 21.

Alert payload labels:

1. `scope=node`
2. `node_id`
3. `alert_type`

## Determinism and Safety

1. Label keys are canonicalized and sorted.
2. Snapshot shape is stable:

```json
{
  "counters": [],
  "histograms": [],
  "gauges": []
}
```

3. Invalid metric operations must not throw.
4. Secrets and auth material must never be included in labels.
