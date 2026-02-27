# Security Model (Phase 19)

## Scope

Security controls for production operations of the distributed execution fabric.

## Federation Authentication and Signing

- All federation calls require authentication.
- All federation calls require request signing where configured.
- Missing or invalid auth/signature must fail closed.

## Token Rotation Policy

- Support dual-token grace period (`currentToken` and `previousToken`).
- Rotation must not require full cluster restart.
- Previous token must expire after configured grace window.
- Rotation events must be audited and correlated to change tickets.

## TLS and mTLS Policy

- mTLS required for cluster-internal communication in production.
- Certificates must be valid and non-expired.
- CA trust roots must be centrally managed.
- Revocation policy must be defined and periodically tested.
- Cert rotation cadence: every 60-90 days recommended.

## Secret Management Policy

- Secrets must be sourced from approved secret manager.
- Secrets must not be persisted in control-plane state files.
- Secrets must not appear in metrics labels/values.
- Secrets must not appear in application logs.
- Secret rotation cadence: at least quarterly, faster for high-risk credentials.

## Access Control and Governance

- Restrict production deploy and runtime actions to approved operator roles.
- Require peer-reviewed change approvals for security-impacting config updates.
- Enforce least-privilege service identity policies.

## Tool Governance in Production

- Maintain explicit allowlist of permitted tools by environment.
- Apply tighter rate caps for high-risk tools.
- Isolate sensitive tools onto restricted worker pools.
- Disable or gate debug and exploratory tool paths in production.

## Security Observability

Track and alert on:

- auth failures and signature verification failures
- token rotation anomalies
- certificate expiry risk window
- unexpected increases in version/config mismatch during rollout windows

## Compliance and Audit Trail

- Log security-relevant changes (token rotation, cert rotation, role changes).
- Retain security audit logs according to policy.
- Verify integrity and retention of audit artifacts regularly.
