# Threat Model (Phase 21)

## Scope

This document captures execution-plane and operational governance threats before LLM amplification.

## Container Breakout Threat Model

Threat: tool runtime escapes container isolation.

Controls:

1. non-root execution user
2. read-only root filesystem
3. capability drop (`ALL`)
4. no host PID/network
5. no host bind mounts
6. strict sandbox validation in adapter and runtime

Residual risk:

1. container runtime/kernel CVEs
2. misconfigured host daemon

## Supply Chain Compromise Model

Threat: malicious or tampered image/package reaches runtime.

Controls:

1. digest-pinned references
2. registry allowlist
3. SBOM generation
4. high/critical CVE fail gates
5. cosign signing and provenance attestation
6. CI fail on `:latest`

Residual risk:

1. zero-day in signed dependencies
2. compromised trusted signer

## Execution Flood Model

Threat: high request burst starves node execution capacity.

Controls:

1. node concurrency cap
2. per-tool concurrency cap
3. minute burst limit
4. hourly quota
5. fail-fast rejection and no automatic retry

Residual risk:

1. coordinated multi-principal abuse within quota envelopes

## Tool Input Injection Model

Threat: attacker crafts payload to trigger unsafe command behavior.

Controls:

1. strict adapter input validation
2. explicit container request schema validation
3. bounded runtime resource policy enforcement
4. no unvalidated execution path bypass

Residual risk:

1. tool-specific parser vulnerabilities

## SSRF Model

Threat: tool invocation reaches internal-only services.

Controls:

1. per-tool egress policy validation
2. internal network default deny posture
3. egress event tracking and anomaly alerts

Residual risk:

1. authorized external egress still permits target abuse

## Egress Abuse Model

Threat: excessive outbound connections cause abuse or data exfiltration.

Controls:

1. egress policy limits per tool
2. per-minute egress event anomaly tracking
3. structured egress audit logs

Residual risk:

1. payload-level exfiltration over allowed channels

## Secret Leakage Model

Threat: credentials leak through logs, files, images, or outputs.

Controls:

1. runtime env-only secret injection
2. no image-embedded secrets
3. no filesystem secret writes
4. no global secret caching
5. output redaction on secret echo
6. `secret.access` metric

Residual risk:

1. unknown secret formats not matched by pattern scanning

## Resource Starvation Model

Threat: a subset of requests consumes node memory/CPU and starves other workloads.

Controls:

1. deterministic arbiter leases
2. memory hard-cap projection
3. CPU share saturation guard
4. idempotent lease release in `finally`
5. lease reconstruction on restart

Residual risk:

1. host-level contention outside runtime accounting

## Circuit Breaker Failure Model

Threat: execution keeps failing without containment.

Controls:

1. runtime-local circuit breaker
2. rejection telemetry (`circuit.open`)
3. no fallback to host execution path

Residual risk:

1. incorrect threshold tuning causing delayed trip or noisy open state
