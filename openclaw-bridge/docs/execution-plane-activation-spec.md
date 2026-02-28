# Execution Plane Activation & Governance (Phase 20 + Phase 21)

## Scope
Phase 20 activates containerized tool execution behind explicit opt-in controls while preserving control-plane behavior. Phase 21 adds operational governance and resource orchestration hardening.

## Control Plane vs Execution Plane
Control-plane modules continue to own routing, scheduling, shard ownership, federation, freeze behavior, partition behavior, version-guard behavior, and idempotency semantics. Execution-plane modules only govern how a selected tool invocation is executed (host process vs container).

## Activation Model
Container execution activates only when both conditions are true:

1. `execution.executionMode="container"`
2. `execution.containerRuntimeEnabled=true`

If container mode is requested while runtime activation is disabled, execution fails fast with `CONTAINER_RUNTIME_DISABLED`.

## Layered Enforcement
Execution safeguards are intentionally redundant:

1. Preflight layer validates production readiness for sandbox, resource, egress, and image policies.
2. Adapter layer validates eligibility and `requested <= policy` resource bounds.
3. Runtime layer re-validates payload shape, policy constraints, and Docker host config enforcement.

No layer assumes another layer is sufficient.

Phase 21 adds a deterministic arbitration layer between supervisor and adapter:

1. node concurrency cap
2. per-tool concurrency cap
3. projected memory hard-cap guard
4. projected CPU saturation guard
5. fail-fast deterministic rejections without retries

## Sandbox Boundary Model
Containers are created with hard runtime constraints:

- non-root user execution
- read-only root filesystem
- dropped Linux capabilities (`ALL`)
- privileged mode disallowed
- host PID namespace disallowed
- host network namespace disallowed
- no host mounts; only managed writable `/scratch`

Sandbox policy validation requires explicit seccomp and AppArmor profile fields.

## Resource Enforcement Philosophy
Per-tool resource envelopes define the maximum runtime budget:

- `cpuShares`
- `memoryLimitMb`
- `maxRuntimeSeconds`
- `maxOutputBytes`

Adapters require explicit requested limits in container mode and reject any dimension above policy. Runtime re-validates limits before container creation and applies cgroup-aligned Docker host limits.

## Network Egress Model
Runtime chooses one of two managed Docker bridge networks based on validated egress policy:

- external-enabled network (`openclaw-execution-net`)
- internal-only network (`openclaw-execution-internal`)

Host networking and automatic port publishing are not allowed.

## Image Provenance Model
Container images are governed by image policy validation:

- digest pinning required (`@sha256:...`)
- registry allowlist enforced in production (GHCR by default)
- `signatureVerified` must be explicitly provided when signature enforcement is required

Production preflight rejects local-only, unpinned, or disallowed-registry images.

## Lifecycle Guarantees
Every container execution follows create/start/capture/remove semantics for both container and scratch volume. Managed resources are labeled with `com.openclaw.execution=true` and are swept periodically to remove stale orphaned resources.

Phase 21 orphan sweep metrics:

1. `container.orphan.cleaned`
2. `orphan.cleanup`

## Secret Governance

Phase 21 secret controls:

1. runtime env-only injection after arbitration
2. no global secret cache
3. no filesystem secret writes
4. output redaction for accidental secret echo
5. `secret.access` metric emission

## Config Reconciliation

Before execution dispatch in production container mode:

1. execution config hash/version is reconciled with peer metadata
2. rolling-upgrade window safety is applied
3. critical mismatch fails closed with `EXECUTION_CONFIG_MISMATCH`

## Failure Isolation and Rollback
Runtime failures are surfaced as normal tool execution errors and do not crash supervisor processes. A runtime-local per-tool circuit breaker fast-fails repeated failures to prevent retry storms. Rollback is configuration-only by setting `execution.containerRuntimeEnabled=false`.

## Migration Path
Phase 20 introduces controlled runtime activation and pinned tool images. Future phases can extend enforcement (for example stronger signature verification and policy distribution), but must preserve control-plane invariants and the layered execution enforcement model.
