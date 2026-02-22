# Burp Suite Skill (via Local Bridge + BionicLink)

This skill gives the agent a safe, scoped interface to Burp Suite Professional by:

1. Burp Extension ("BionicLink") running inside Burp on `http://127.0.0.1:8090`
2. Local Node bridge (OpenClaw bridge service) on `http://127.0.0.1:8787`

The bridge enforces:
- Scope Lock (Burp Target Scope) for any outbound requests / scans.
- Traffic Summarization Protocol (TSP) to keep token usage low.

## Tools

### `burp_get_history`
Retrieve recent proxy traffic to understand app logic and identify candidate endpoints/parameters.

Parameters:
- `limit` (number, optional): max items to retrieve (suggest 20-50)
- `fromId` (number, optional): poll newer items (bridge uses 1-based IDs)
- `inScope` (boolean, optional): only items currently in Burp Target Scope

### `burp_analyze_request`
Send a custom request (Repeater-style) to test a specific hypothesis (non-destructive).

Parameters:
- `url` (string, required)
- `method` (string, optional, default `GET`)
- `headers` (object, optional): key/value headers
- `body` (string, optional)

### `burp_active_scan`
Launch a targeted active scan (high noise). Use only when a specific suspicious endpoint is identified.

Parameters:
- `url` (string, required)
- `method` (string, optional, default `GET`)
- `requestId` (number, optional): 1-based ID referencing Burp proxy history (best effort)

Notes:
- The bridge will block this unless `BURP_ALLOW_ACTIVE_SCAN=true` is set in the bridge environment.

### `burp_get_raw_request`
Retrieves unredacted session data for a specific request ID for authenticated testing.

Parameters:
- `messageId` (number, required): 1-based ID from Burp proxy history

Notes:
- The bridge will refuse this unless `BURP_ALLOW_RAW_DATA=true` is set in the bridge environment.
- The bridge performs a mandatory Burp Target Scope check before returning any data.

### `burp_zero_click_triage`
Run a safety-focused heuristic pass over recent Burp history to identify likely server-side autonomous processing surfaces (e.g., webhook/callback/queue/parser paths) for zero-click style research triage.

Parameters:
- `limit` (number, optional, default `75`): number of history items to inspect
- `maxCandidates` (number, optional, default `12`): top candidates to return
- `inScope` (boolean, optional, default `true`): restrict to Burp Target Scope entries
- `fromId` (number, optional): incremental polling start ID

Notes:
- Defensive triage only; this tool does not generate exploit payloads.
- Use with `/Users/trevorrobey/.openclaw/skills/zero-click-rce-bounty-research/SKILL.md` for safe planning/reporting.
- Follow with targeted `burp_analyze_request` only on explicit candidate endpoints.

## Environment

The tool client uses:
- `OPENCLAW_BRIDGE_BASE_URL` (optional) default `http://127.0.0.1:8787`
