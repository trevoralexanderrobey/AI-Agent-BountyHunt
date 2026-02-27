# Production Topology Model (Phase 19)

## Scope and Guarantees

This document defines deployment topology choices for the distributed execution fabric.

- Execution semantics are unchanged.
- Cluster routing, idempotency, partition containment, and version guard behavior are unchanged.
- This document describes operational architecture, not runtime algorithm changes.

## Canonical Topologies

### A) Single-region Cluster

- Minimum nodes: 3 core nodes.
- Consensus expectation: none (deterministic control plane with containment safeguards).
- Placement: shared low-latency network zone.
- Ingress: load balancer in front of HTTP/API ingress.
- Trust: shared mTLS CA for all cluster-internal traffic.
- Target latency:
- Intra-node p95: <= 10 ms
- Federation call p95: <= 75 ms
- Blast radius: full region outage impacts full cluster.
- Use when: simple production footprint and low operational overhead are primary.
- Do not use when: region-level availability must survive full region loss.

### B) Multi-AZ Cluster

- Minimum nodes: 3 core nodes across at least 2 AZs.
- Consensus expectation: none.
- Placement: anti-affinity across zones, zone-aware scheduling.
- Ingress: regional LB with zone-aware health checks.
- Target latency:
- Intra-AZ p95: <= 10 ms
- Cross-AZ p95: <= 25 ms
- Federation call p95: <= 90 ms
- Blast radius: single AZ failure is tolerated; region failure is not.
- Use when: higher resilience than single-zone while staying single-region.
- Do not use when: cross-region continuity is mandatory.

### C) Multi-region Active-Passive

- Minimum nodes: active region >= 3 core nodes, passive region >= 3 warm/cold standby nodes.
- Consensus expectation: none across regions.
- Traffic: primary region active; secondary region cold or warm standby.
- Failover: manual or automated DNS/LB cutover.
- Control-plane state: replicated from primary to standby via backup pipeline.
- Target latency:
- Intra-region p95: <= 25 ms
- Inter-region replication p95: <= 250 ms
- Blast radius: single region failure can be mitigated via failover runbook.
- Use when: region DR is required with conservative operational behavior.
- Do not use when: simultaneous multi-region active write/serve is required.

### D) Multi-region Active-Active (Non-consensus)

- Minimum nodes: each region runs an independent 3+ node cluster.
- Consensus expectation: none, and no global shard consensus.
- Cross-region shard ownership: prohibited.
- Cross-region federation: disabled.
- Traffic split: DNS/LB-based, region-local routing only.
- Target latency:
- Region-local p95 federation: <= 90 ms
- Cross-region control path: not part of cluster ownership path
- Blast radius: region failure impacts region-local slice only; no cross-region ownership coupling.
- Use when: geographic traffic distribution with loose inter-region coupling.
- Do not use when: strict global consistency or single global ownership plane is required.

## Non-consensus Warning

This cluster does not implement quorum-based consensus. Under network partition, both sides may continue serving stable shards independently. This is a design choice and must be considered for strict-consistency or multi-region requirements.

## Quorum Expectations

- There is no Raft/quorum write election.
- Safety depends on deterministic ownership, idempotency, partition containment, and freeze/convergence guards.
- "Majority" in this system is used for containment policy, not consensus commit semantics.

## Node Count and Failure Domain Guidance

- Production cluster mode requires expected node count >= 3.
- Single-node "cluster" is not allowed in production.
- Expected node count is an explicit deployment input for preflight checks.
- Recommended max per region: 24 core nodes before introducing additional region-local clusters.

## Allowed Latency Envelope

- p95 local execution latency target: <= 150 ms (skill-dependent).
- p95 federation call latency target: <= 120 ms.
- p99 federation timeout budget: <= 2 s for normal operation.
- If sustained latency exceeds envelope, scale out or isolate high-cost workloads.

## Topology Selection Matrix

- Prefer single-region for early production where regional DR is externalized.
- Prefer multi-AZ for resilient single-region operations.
- Prefer active-passive for controlled DR with clear failover runbooks.
- Prefer active-active only when each region can be operationally independent and strict global consistency is not required.
