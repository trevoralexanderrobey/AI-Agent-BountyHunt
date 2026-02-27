# Infrastructure Reference (Phase 19)

## Kubernetes Reference

### Workload model

- Use `StatefulSet` for stable identity and durable state path mapping where needed.
- Use `Deployment` for stateless ingress-only roles.

### Placement and resilience

- Enforce pod anti-affinity for core nodes.
- Spread core nodes across AZs.
- Use PodDisruptionBudget to avoid simultaneous control-plane capacity loss.

### Storage

- Use PersistentVolume for node-specific control-plane state.
- Ensure volume mapping remains node-unique and stable across restarts.

### Health probes

- Liveness probe: process health endpoint.
- Readiness probe: cluster readiness and serving state.
- Startup probe: longer threshold for cold start.

## Docker Compose Reference

- Minimal production-like topology requires 3+ core services.
- Use separate named volumes per node.
- Explicitly set node identity and cluster/federation settings for each service.

### Volume pattern

- `node-a-state:/app/data/node-a`
- `node-b-state:/app/data/node-b`
- `node-c-state:/app/data/node-c`

## Systemd Reference

- Use `Restart=on-failure` with sane backoff.
- Use graceful shutdown signal and timeout.
- Forward logs to central log pipeline.
- Ensure service unit captures environment file with validated config.

## Environment Variable Matrix

Required in production tooling context:

- `NODE_ENV=production`
- `SUPERVISOR_NODE_ID`
- `SUPERVISOR_SOFTWARE_VERSION` (or documented software version source)
- `TOPOLOGY_EXPECTED_NODE_COUNT`
- `CLUSTER_CONTROL_PLANE_PHASE` (or capability override)
- `CLUSTER_MANAGER_STATE_PATH` (node-isolated template/path)

Security/TLS-related (when enabled):

- `TLS_ENABLED=true`
- `TLS_CERT_PATH`
- `TLS_KEY_PATH`
- `MTLS_ENABLED=true`
- `MTLS_CA_PATH`

Optional but recommended:

- `DEPLOYMENT_VERSION_TARGETS` (comma-delimited version list)

## Version Target Scope

- `DEPLOYMENT_VERSION_TARGETS` maps to `deployment.versionTargets` in preflight input.
- Preflight validates local version against each target version.
- Preflight does not guarantee that all target versions are mutually compatible.
- Operators must enforce rollout order to preserve compatibility windows.
