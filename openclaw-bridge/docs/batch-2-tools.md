# Batch 2 Tools (Phase 11C)

## Overview

Phase 11C adds medium-complexity CLI adapters:

1. `hashcat`
2. `sqlmap`
3. `nikto`

All adapters enforce strict input validation, bounded execution, bounded output, and `spawn()` argument-array execution with `shell: false`.

## hashcat Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/hashcat-adapter.js`

### Input Schema

```json
{
  "hash": "5d41402abc4b2a76b9719d911017c592",
  "hashType": 0,
  "attackMode": 0,
  "wordlist": "rockyou-mini",
  "maxRuntime": 60
}
```

### Supported Hash Types

1. `0` MD5
2. `100` SHA1
3. `1000` NTLM
4. `1400` SHA256
5. `1700` SHA512
6. `1800` sha512crypt
7. `3200` bcrypt

### Attack Modes

1. `0` dictionary
2. `3` brute-force

### Wordlists

1. `rockyou-mini`
2. `top-1000`
3. `common-passwords`

### Output Schema

```json
{
  "hash": "...",
  "cracked": true,
  "password": "hello",
  "runtime_seconds": 12,
  "status": "cracked"
}
```

Status values: `cracked`, `exhausted`, `timeout`, `error`.

### Runtime Limits

1. max runtime: `300s`
2. adapter timeout: `300000ms`
3. max output: `1MB`

## sqlmap Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/sqlmap-adapter.js`

### Input Schema

```json
{
  "url": "http://target.example/page?id=1",
  "method": "GET",
  "level": 1,
  "risk": 1,
  "technique": "BEUST",
  "maxRuntime": 120
}
```

### Constraints

1. URL must be `http/https`.
2. Method must be `GET` or `POST`.
3. `level` range: `1..5`.
4. `risk` range: `1..3`.
5. Technique characters restricted to `B,E,U,S,T`.
6. `maxRuntime` maximum: `300s`.

### Output Schema

```json
{
  "url": "http://target.example/page?id=1",
  "vulnerable": true,
  "injection_points": [
    {
      "parameter": "id",
      "type": "GET",
      "payload": "..."
    }
  ],
  "dbms": "MySQL",
  "runtime_seconds": 32,
  "status": "vulnerable"
}
```

Status values: `vulnerable`, `not_vulnerable`, `timeout`, `error`.

### Runtime Limits

1. max runtime: `300s`
2. adapter timeout: `300000ms`
3. max output: `5MB`

## nikto Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/nikto-adapter.js`

### Input Schema

```json
{
  "host": "example.com",
  "port": 443,
  "ssl": true,
  "tuning": "123456789",
  "maxRuntime": 300
}
```

### Constraints

1. `host` must be valid hostname or IP.
2. `port` range: `1..65535`.
3. `ssl` must be boolean if provided.
4. `tuning` may include `0-9` and `a/b/c/x`.
5. `maxRuntime` maximum: `600s`.

### Output Schema

```json
{
  "host": "example.com",
  "port": 443,
  "ssl": true,
  "vulnerabilities": [
    {
      "id": "OSVDB-3092",
      "description": "...",
      "uri": "/admin",
      "method": "GET"
    }
  ],
  "server_info": {
    "server": "nginx",
    "headers": {
      "x-frame-options": "DENY"
    }
  },
  "runtime_seconds": 47,
  "status": "completed"
}
```

Status values: `completed`, `timeout`, `error`.

### Runtime Limits

1. max runtime: `600s`
2. adapter timeout: `600000ms`
3. max output: `10MB`

## Security Constraints

1. No shell execution. All commands use `spawn()` with argument arrays.
2. Input values are validated and whitelisted where possible.
3. Timeout is hard-enforced with process kill.
4. Output capture is size-limited.
5. Internal host path patterns are redacted from returned text payloads.
