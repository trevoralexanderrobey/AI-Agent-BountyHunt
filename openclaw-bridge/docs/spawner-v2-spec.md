# Spawner v2 Spec

This document defines Skill Spawner 2.0 for host-side container lifecycle control.

## Scope

- Control plane only.
- Spawner is the only component allowed to communicate with Docker.
- Skill Runtime behavior is unchanged.
- MCP server behavior is unchanged.

## Module

- File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/spawner/spawner-v2.js`
- Export: `createSpawnerV2()`

`createSpawnerV2()` returns:

1. `initialize()`
2. `spawnSkill(slug)`
3. `terminateSkill(containerId)`
4. `getSkillState(containerId)`
5. `listSkillStates()`
6. `cleanupOrphans()`

All APIs return structured objects. Failures return:

```json
{
  "ok": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Error message",
    "details": {}
  }
}
```

## Image Allowlist

Spawner enforces a static image allowlist:

```json
{
  "nmap": "openclaw-nmap-skill"
}
```

Unknown slugs are rejected with `INVALID_SLUG`.

## Container Lifecycle

State machine:

- `CREATING`
- `STARTING`
- `READY`
- `FAILED`
- `TERMINATING`
- `TERMINATED`

Registry model (`Map<containerId, entry>`):

```json
{
  "slug": "string",
  "token": "string",
  "state": "CREATING|STARTING|READY|FAILED|TERMINATING|TERMINATED",
  "createdAt": "epoch_ms",
  "name": "string",
  "networkAddress": "string|null",
  "lastError": "string|null"
}
```

`spawnSkill(slug)` success payload:

```json
{
  "containerId": "string",
  "name": "string",
  "slug": "string",
  "networkAddress": "http://<container_ip>:4000/mcp",
  "token": "string",
  "state": "READY"
}
```

## Network Model

- Docker network name: `openclaw-net`
- Driver: `bridge`
- Containers are attached to `openclaw-net`
- No host port publishing is used

Health probing uses direct container IP:

1. Read container IP with `docker inspect` from `.NetworkSettings.Networks["openclaw-net"].IPAddress`
2. Probe `POST http://<container_ip>:4000/mcp`
3. Send bearer token auth and JSON-RPC `health` method

Health success condition:

- Valid JSON-RPC 2.0 response is returned, regardless of `result.ok`.

Dual probe strategy:

1. Primary: host to container IP probe (direct `http://<container_ip>:4000/mcp`).
2. Fallback: only when primary fails due to transport timeout/connection error, run `docker exec` probe inside the container against `http://localhost:4000/mcp`.
3. Explicit JSON-RPC errors from the primary probe do not trigger fallback.
4. Overall health timeout remains `15s` with `500ms` poll cadence.

Compatibility note:

- The fallback path addresses host-to-container IP routing limitations seen on macOS Docker Desktop/Colima environments without changing container security posture.

## Security Constraints

Spawner enforces:

- No privileged mode
- No host volume mounts
- No docker socket mounts into skill containers
- No arbitrary image names
- No arbitrary docker flags
- No arbitrary environment injection
- No full token logging
- Tokens are cleared from registry records once a container is terminated

Container runtime flags:

- `--cap-drop ALL`
- `--memory 512m`
- `--cpus 1`
- `--pids-limit 128`
- `--read-only`
- `--security-opt no-new-privileges`

Spawner injects only:

- `MCP_SKILL_TOKEN=<generated token>`
- `SKILL_EXECUTION_TIMEOUT_MS=60000`
- `TOOL_NAME=<slug>`
- `SKILL_SLUG=<slug>`

## Failure Handling

Structured error codes:

1. `INVALID_SLUG`
2. `DOCKER_UNAVAILABLE`
3. `NETWORK_CREATE_FAILED`
4. `SPAWN_FAILED`
5. `HEALTHCHECK_TIMEOUT`
6. `HEALTHCHECK_FAILED`
7. `INSPECT_FAILED`
8. `CONTAINER_NOT_FOUND`
9. `TERMINATE_FAILED`
10. `CLEANUP_FAILED`

Behavior:

- Health timeout (`15s`) triggers stop/remove and marks state `FAILED`.
- Termination uses graceful `docker stop -t 5` then `docker rm`.
- Startup initialization creates network if missing and removes stale `openclaw-skill-*` containers.
- Orphan cleanup applies strict prefix verification on inspected container names before removal.

## Resource and Timing Defaults

- Execution timeout env for containers: `60000ms`
- Health timeout per spawn: `15000ms`
- Health poll interval: `500ms`
- MCP endpoint port inside container: `4000`

## Operational Validation Commands

From `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge`:

```bash
node -e "const { createSpawnerV2 } = require('./spawner/spawner-v2.js'); console.log(Object.keys(createSpawnerV2()));"
```

```bash
node -e "(async()=>{const { createSpawnerV2 } = require('./spawner/spawner-v2.js'); const s=createSpawnerV2(); console.log(await s.initialize()); console.log(await s.spawnSkill('nmap')); })().catch(console.error)"
```

```bash
docker exec <container_id> id -u
```

```bash
docker ps --filter name=openclaw-skill-
```

```bash
node -e "(async()=>{const { createSpawnerV2 } = require('./spawner/spawner-v2.js'); const s=createSpawnerV2(); const a=await s.spawnSkill('nmap'); console.log(await s.terminateSkill(a.containerId)); })().catch(console.error)"
```

Expected checks:

1. `spawnSkill("nmap")` transitions to `READY`.
2. `terminateSkill(containerId)` transitions to `TERMINATED`.
3. Invalid slug returns `INVALID_SLUG`.
4. Container user is non-root (`id -u` is not `0`).
5. Container has no host ports published.
6. Two spawns produce unique tokens.
7. Cleanup removes stale `openclaw-skill-*` containers at startup.
