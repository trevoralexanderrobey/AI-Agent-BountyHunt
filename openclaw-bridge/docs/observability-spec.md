# Observability Spec

## Scope

Phase 8 adds deterministic, in-memory telemetry to Supervisor v1 and Spawner v2.

- No runtime contract changes.
- No JSON-RPC protocol changes.
- No external exporters.
- No file/network I/O from metrics code.

## Module

- Metrics module: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/observability/metrics.js`
- Export: `createMetrics()`

API:

1. `increment(counterName, labels?)`
2. `observe(histogramName, value, labels?)`
3. `gauge(name, value, labels?)`
4. `snapshot()`
5. `reset()`

## Determinism

- Labels are canonicalized with lexicographically sorted keys.
- Snapshot output is sorted by metric name and canonicalized labels.
- Snapshot shape is always:

```json
{
  "counters": [],
  "histograms": [],
  "gauges": []
}
```

## Histogram Model

Fixed bucket boundaries:

`[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf]`

Observation rules:

- Ignore values where `!Number.isFinite(value)`.
- Ignore values where `value < 0`.
- Invalid observations must never throw.

## Safety Guarantees

- `increment`, `observe`, and `gauge` are non-throwing.
- Invalid names/labels/values are ignored or normalized.
- Metrics failures must never alter execution flow.
- Metrics must not contain tokens, authorization headers, job payloads, or container network addresses.

## Namespace Ownership

### Supervisor namespace (`supervisor.*`)

Owned by Supervisor routing decisions and pool lifecycle accounting.

Counters:

1. `supervisor.executions.total`
2. `supervisor.executions.success`
3. `supervisor.executions.error`
4. `supervisor.executions.capacity_rejected`
5. `supervisor.spawn.attempt`
6. `supervisor.spawn.success`
7. `supervisor.spawn.failure`
8. `supervisor.instance.reaped`
9. `supervisor.instance.terminated`
10. `supervisor.instance.failed`

Histograms:

1. `supervisor.execution.duration_ms`
2. `supervisor.spawn.duration_ms`

Gauges:

1. `supervisor.instances.total`
2. `supervisor.instances.ready`
3. `supervisor.instances.busy`
4. `supervisor.pending_spawns`

### Spawner namespace (`spawner.*`)

Owned by Spawner container lifecycle events.

Counters:

1. `spawner.spawn.attempt`
2. `spawner.spawn.success`
3. `spawner.spawn.failure`
4. `spawner.terminate.success`
5. `spawner.terminate.failure`
6. `spawner.health.timeout`

Histograms:

1. `spawner.spawn.duration_ms`

## Drift Rules

- Supervisor spawn metrics are incremented once per logical routing spawn decision.
- Spawner spawn metrics are incremented once per spawner lifecycle outcome.
- Health probe retries do not increment spawn attempt counters.
- Cross-namespace duplication is allowed; within-namespace duplication for a single event is not.

## Integration

Supervisor:

```js
const supervisor = createSupervisorV1({ metrics });
const snapshot = supervisor.getMetrics();
```

Spawner:

```js
const spawner = createSpawnerV2({ metrics });
```

If no metrics object is injected, both modules operate with safe no-op metrics behavior.
