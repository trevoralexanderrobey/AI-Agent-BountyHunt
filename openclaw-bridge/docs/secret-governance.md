# Secret Governance (Phase 21)

## Scope

This policy governs execution-plane secret handling for containerized tool execution.

## Non-Negotiable Rules

1. Secrets must not be embedded in container images.
2. Secrets must be injected at runtime through environment variables only.
3. Secrets must not be written to filesystem artifacts.
4. Secrets must not be logged, echoed in responses, or cached globally.
5. Secret reads must emit `secret.access` without exposing values.

## Build-Time Enforcement

CI/CD must fail if image layers contain:

1. `.env` files
2. private keys (`BEGIN PRIVATE KEY`)
3. AWS credential patterns
4. GitHub token patterns
5. known high-confidence secret signatures

## Runtime Injection Boundary

Injection order is fixed:

1. request authentication and identity check
2. arbitration and quota checks
3. per-execution secret preparation
4. runtime dispatch

No secret injection is allowed before arbitration success.

## Logging and Output Controls

1. Secret values are never logged.
2. Sensitive key names are hashed before audit/log context output.
3. Tool output is scanned for accidental secret echo and redacted before response emission.

## Caching and Retention

1. No process-wide secret cache is allowed.
2. Secrets are scoped to a single execution and discarded after completion.
3. No decrypted secret material is persisted in state snapshots or queue payloads.

## Rotation Policy

1. Rotation is externalized to secret source systems (vault/parameter store/env provider).
2. Rotation does not require container rebuilds.
3. Rotation cadence:
   - high-risk tokens: <= 24 hours
   - standard API credentials: <= 30 days
4. Emergency rotation immediately revokes previous credentials and updates runtime secret source.

## Audit Signals

Required metrics and logs:

1. `secret.access` with hashed key identifier
2. `secret_output_redaction` audit event on detected secret echo
