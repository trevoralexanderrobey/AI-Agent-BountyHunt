# Execution Plane Hardening Spec (Phase 19A)

## Scope

Phase 19A introduces execution-plane hardening scaffolding for production readiness without enabling real containerized tool execution.

This phase does not change:

- supervisor routing semantics
- partition containment behavior
- freeze or convergence behavior
- version-guard semantics
- idempotency behavior
- default host tool execution behavior

## Control Plane vs Execution Plane

- Control plane: supervisor, federation, cluster coordination, deployment guardrails.
- Execution plane: tool execution runtime, sandbox policy, resource policy, egress policy, container lifecycle controls.

Separation goal: execution hardening evolves independently from control-plane routing logic.

## Sandbox Boundary Model

Default required posture for container execution policy:

- run as non-root
- drop all Linux capabilities
- privileged mode disabled
- host PID/network namespaces disabled
- host mounts disabled
- read-only root filesystem
- writable scratch volume only
- seccomp profile required
- AppArmor profile required

Phase 19A validates policy definitions only; enforcement backends are deferred to Phase 20.

## Resource Enforcement Philosophy

Per-tool resource envelope schema:

- `cpuShares`
- `memoryLimitMb`
- `maxRuntimeSeconds`
- `maxOutputBytes`

Principles:

- hard timeout required
- memory ceiling required
- adapter container path requires explicit requested limits
- requested limits must not exceed policy limits (`requested <= policy` for each dimension)

This preserves runtime safety even if preflight is bypassed.

## Network Egress Model

Per-tool egress policy schema:

- `allowedExternalNetwork`
- `allowedCIDR`
- `rateLimitPerSecond`

Phase 19A provides validation scaffolding only; no firewall/traffic enforcement is enabled yet.

## Image Provenance Model

Image policy requires:

- allowlisted registries
- digest pinning (no floating tags, no `:latest`)
- signature verification flag

Production mode rejects:

- unpinned images
- local-only image references
- images outside allowlisted registries

## Threat Model for Tool Execution

Primary threats addressed by scaffolding:

- privilege escalation from weak container sandbox config
- unbounded resource consumption
- uncontrolled network egress definitions
- untrusted image provenance
- missing lifecycle auditability

Phase 19A reduces configuration risk but does not yet activate real container enforcement.

## Migration Path to Phase 20

Phase 20 will:

- wire real container execution backends
- enable enforcement of sandbox/resource/egress policies
- introduce approved tool image enablement and rollout controls

Phase 19A ensures required interfaces, guardrails, and policy contracts are in place first.

## Transitional Host Execution Rationale

Host execution remains default in Phase 19A to avoid runtime drift while hardening contracts are introduced.

Host execution is transitional and not considered production-hardened long-term. Container execution remains opt-in and guarded until full Phase 20 enablement.
