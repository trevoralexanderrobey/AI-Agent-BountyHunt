# SLO / SLI Specification (Phase 19)

## Scope

Defines measurable reliability and performance objectives for production operations.

## Measurement Window

- Standard reporting window: rolling 30 days.
- Supplementary operational review: daily and weekly summaries.

## Availability

### SLO

- Cluster availability: 99.9% monthly.

### SLI

`availability = successful_requests / total_requests`

- Exclude approved maintenance windows.
- Include both local and federated execution paths.

## Consistency

### SLOs

- No duplicate execution across nodes for idempotent requests.
- No shard ownership drift under stable membership.

### SLIs

- `duplicate_execution_events` (target: 0)
- `unexpected_shard_owner_changes_under_stable_membership` (target: 0)

## Latency

### SLOs

- p95 local execution latency within agreed per-skill objective.
- p95 federation call latency <= 120 ms (baseline target, adjust by environment).

### SLIs

- `p95_local_exec_latency_ms`
- `p95_federation_call_latency_ms`

## Durability

### SLOs

- Control-plane restart recovery <= 60 seconds for node-level restart.
- Snapshot restoration readiness <= 120 seconds after process restart.

### SLIs

- `restart_to_ready_duration_ms`
- `snapshot_restore_duration_ms`

## Alerting and Burn Policy

- Alert when 2-hour projected error budget burn exceeds threshold.
- Escalate to incident mode if burn remains elevated for 30 minutes.
- Pause risky rollout operations during active burn events.

## Reporting Requirements

- Daily health report with SLI trends.
- Weekly SLO compliance summary.
- Monthly executive reliability review with remediation backlog.
