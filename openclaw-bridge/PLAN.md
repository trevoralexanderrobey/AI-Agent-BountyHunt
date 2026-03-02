# Supervisor Migration Structural Hardening Plan

## Scope
This pass is structural hardening only. `SUPERVISOR_MODE` remains `false` by default and no Phase 2 enforcement activation is included here.

## Canonical Router
- Canonical execution router is `src/core/execution-router.ts`.
- Entrypoints delegate through router (with legacy fallbacks for compatibility):
  - `bridge/server.ts`
  - `http/handlers.js` (via adapter context)
  - `github-pro-mcp/src/server.ts`

## Router-Only Enforcement Responsibilities
- Tool namespace and capability checks.
- Role authorization (`supervisor`, `internal`, `admin`, `anonymous`).
- Internal bypass validation (trusted in-process or internal token).
- Mutation guard.
- Workspace path sandboxing for supervisor tools.
- Audit logging.
- Role-aware `tools/list` filtering.

## Internal Bypass Hardening
- External payload `internal=true` is not trusted by itself.
- Bypass is allowed only when one of these is true:
  - trusted in-process caller context
  - valid `SUPERVISOR_INTERNAL_TOKEN`
- External/internal-flag spoof attempts are rejected with `UNAUTHORIZED_INTERNAL_BYPASS`.

## Workspace-Relative Token Resolution
- Bearer token file is resolved with:
  - `path.join(workspaceRoot, ".cline", "cline_mcp_settings.json")`
- Environment fallback is preserved for compatibility:
  - `BRIDGE_AUTH_TOKEN` / `SUPERVISOR_AUTH_TOKEN`

## Audit Logging Hardening
- Supervisor audit log path:
  - `<workspaceRoot>/.openclaw/audit.log`
- Async append queue (non-blocking execution path).
- Rotation at 10MB to `audit.log.1`.
- Logging failures are fail-open.

## Role-Aware `tools/list`
- Role is derived from auth/internal trust context.
- Visible tools are filtered by capability matrix.
- Legacy tool visibility is role-aware through `legacyVisibleToolsByRole`.

## Rollback Playbook
1. Set `SUPERVISOR_MODE=false`.
2. Set `SUPERVISOR_AUTH_PHASE=compat`.
3. Restart bridge services.
4. Verify legacy `bridge_execute_tool` behavior.
5. Verify jobs can submit and execute.
6. Verify MCP SSE tools/list and tools/call remain healthy.

## Optional Improvement Included
- Import-boundary guard added:
  - `executionRouter` is the only module allowed to import runtime `supervisor-registry.json`.
  - enforced by test: `tests/execution/supervisor-registry-import-boundary.test.js`.
