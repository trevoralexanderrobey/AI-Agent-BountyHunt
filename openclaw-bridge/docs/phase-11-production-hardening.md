# Phase 11 Production Hardening

## Scope

Phase 11 hardens the existing Phase 10 ingress and control plane without changing runtime execution semantics, lifecycle state machines, or MCP contracts.

Implemented components:

1. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/tls-config.js`
2. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/request-signing.js`
3. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/security/audit-logger.js`
4. `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/monitoring/prometheus-exporter.js`
5. TLS/signing/prometheus integration in `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/http/server.js`
6. Audit integration in `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/supervisor/supervisor-v1.js`

## TLS and mTLS Setup

### Environment Variables

1. `TLS_ENABLED=true|false` (default `false`)
2. `TLS_CERT_PATH=/absolute/path/fullchain.pem`
3. `TLS_KEY_PATH=/absolute/path/privkey.pem`
4. `MTLS_ENABLED=true|false` (default `false`)
5. `MTLS_CA_PATH=/absolute/path/client-ca.pem`

### Enforcement

1. TLS minimum version: `TLSv1.2`.
2. Certificate chain is validated on startup.
3. Expired certificates fail startup.
4. When mTLS is enabled:
   - client certificate is required (`requestCert=true`)
   - client certificate must chain to configured CA (`rejectUnauthorized=true`).

### Certificate Rotation

1. Replace cert/key files atomically.
2. Restart ingress process to reload certificates.
3. Verify startup logs show updated expiry date and mTLS mode.

## Request Signing

### Environment Variables

1. `REQUEST_SIGNING_ENABLED=true|false` (default `false`)
2. `REQUEST_SIGNING_SECRET=<hmac-secret>`

### Scheme

1. Canonical payload: stable JSON stringify with recursively sorted keys.
2. Signature: `base64(HMAC_SHA256(canonical_payload, secret))`.
3. Header: `X-Signature`.
4. Verification:
   - enabled on all JSON `POST` requests
   - missing/invalid signature returns `401 INVALID_SIGNATURE`.

### Secret Management

1. Keep secret in environment or secret manager.
2. Never hardcode in source.
3. Rotate on schedule or incident response.

## Audit Logging

### Environment Variables

1. `AUDIT_LOG_ENABLED=true|false` (default `true`)
2. `AUDIT_LOG_PATH=./logs/audit.log` (default if unset)
3. `AUDIT_LOG_ROTATE_DAILY=true|false` (default `true`)
4. `AUDIT_LOG_MAX_BYTES=104857600` (100MB default)

### Record Format

```json
{
  "timestamp": "ISO8601",
  "event": "execute|spawn|terminate|auth_failure|circuit_trip|queue_overflow|shutdown",
  "principal_id": "string",
  "slug": "string",
  "request_id": "string",
  "status": "success|failure",
  "details": {}
}
```

### Security Rules

1. No token/secret/password/authorization/signature values are written.
2. Log file is append-only under normal operation.
3. Rotation uses rename with timestamp suffix.

## Prometheus Exporter

### Environment Variable

1. `PROMETHEUS_EXPORTER_ENABLED=true|false` (default `false`)

### Endpoint

1. `GET /metrics/prometheus`
2. Content-Type: `text/plain; version=0.0.4; charset=utf-8`
3. Exports supervisor/spawner/http metrics converted from in-memory snapshots:
   - counters
   - gauges
   - histograms (bucket/sum/count)
4. Includes queue length, circuit breaker state, and skill health gauges when present.

## Deployment Checklist

1. Set required TLS variables if HTTPS is enabled.
2. Set request-signing secret if signing is enabled.
3. Ensure log directory exists and is writable by service user.
4. Enable Prometheus endpoint only on trusted network paths.
5. Confirm service startup logs show:
   - protocol (`http` or `https`)
   - mTLS mode
   - certificate expiry (TLS mode only).
6. Validate `GET /health`, `GET /metrics`, and (if enabled) `GET /metrics/prometheus`.

## Operational Procedures

### Certificate Renewal

1. Replace certificate files.
2. Restart service.
3. Verify expiry timestamp in startup logs.
4. Run mTLS smoke test for client cert validation.

### Audit Log Archival

1. Ship rotated audit files to centralized storage.
2. Apply retention policy aligned with compliance requirements.
3. Restrict read access to security/operations roles.

### Metrics Retention

1. Internal in-memory metrics reset on process restart.
2. Use Prometheus scraping for durable historical retention.

## Security Considerations

1. Rotate `REQUEST_SIGNING_SECRET` periodically.
2. Restrict file permissions on TLS keys and audit logs.
3. Enforce TLS 1.2+ only.
4. Keep mTLS CA bundle current and audited.
5. Avoid exposing metrics endpoints publicly without network controls.
