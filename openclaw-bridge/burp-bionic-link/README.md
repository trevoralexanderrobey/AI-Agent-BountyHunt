# BionicLink (Burp Suite Pro Extension)

BionicLink is a Burp Suite Pro extension (Java) built on the PortSwigger Montoya API. It exposes a small loopback HTTP server inside Burp so the local bridge can:
- Read recent proxy history
- Send a custom request (Repeater-like)
- Start an audit (Scanner), guarded by Burp scope + bridge env flags

Default base URL:
- `https://127.0.0.1:8090`

## Build

From:
- `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/burp-bionic-link`

Run:

```bash
./gradlew jar
```

Output jar:
- `openclaw-bridge/burp-bionic-link/build/libs/BionicLink-0.1.0.jar`

## Load Into Burp

1. Open Burp Suite Pro
2. Extensions
3. Add
4. Select:
   - `openclaw-bridge/burp-bionic-link/build/libs/BionicLink-0.1.0.jar`

## Verify

```bash
curl -s https://127.0.0.1:8090/health
```

## Endpoints

- `GET /health`
- `GET /history?limit=...&fromId=...&inScope=true|false`
- `GET /scope?url=https%3A%2F%2Fexample.com%2F`
- `POST /repeater` (JSON request payload)
- `POST /scan` (JSON request payload)

## Port Override (Optional)

You can override the port BionicLink uses by setting an environment variable for Burp:
- `BIONICLINK_PORT=8090`

If you change this, also update:
- `openclaw-bridge/.env` (`BIONICLINK_BASE_URL=...`)

