# LLDB Crash Triage Bridge (Defensive)

This module installs an LLDB stop-hook that, on crash-like stops (signal/exception), captures a small crash context bundle (registers + backtrace) and POSTs it to the local OpenClaw bridge service at `POST /lldb-stop`.

The bridge creates a normal job so artifacts land in `${BRIDGE_WORKSPACE_ROOT}/jobs/<jobId>/...`, including:
- `LLDB_STOP_EVENT.json`
- `MISSION_REPORT.md`

This is defensive debugging triage only (no exploit/payload guidance).

## Start The Bridge

From the vault root:

```bash
cd "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge"
npm run bridge:start
# For local dev with BRIDGE_HTTP=true:
curl --fail --silent http://127.0.0.1:8787/health | jq
# If TLS is enabled and you trust the cert: use https://127.0.0.1:8787/health
```

## Import The LLDB Hook

In LLDB:

```lldb
command script import "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/lldb/triage_bridge.py"
```

If it installs successfully, you'll see:
- `triage_bridge: installed stop-hook ...`

## Trigger A Crash And Verify

1) Trigger a crash/exception stop in your debug target.

2) Confirm a new job exists:

```bash
curl --silent http://127.0.0.1:8787/jobs | head
```

3) Inspect artifacts under `${BRIDGE_WORKSPACE_ROOT}/jobs/<jobId>/`:
- `LLDB_STOP_EVENT.json`
- `MISSION_REPORT.md`

## Disable The Hook

In LLDB:

```lldb
target stop-hook list
target stop-hook delete <id>
```

## Fallback Behavior

If the bridge is down/unreachable, the hook writes a fallback JSON file:
- `~/.openclaw/logs/lldb-triage/<timestamp>-pid<pid>.json`

