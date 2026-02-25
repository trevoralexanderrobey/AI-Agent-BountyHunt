# Batch 3 Tools (Phase 11D)

## Overview

Phase 11D adds high-complexity tool adapters:

1. `aircrack`
2. `msfvenom`
3. `ffuf`

These adapters enforce strict input allowlists, no-shell execution, runtime/output bounds, and output sanitization.

## aircrack Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/aircrack-adapter.js`

### Supported Key Types

1. `wep`
2. `wpa` (WPA/WPA2)

### Input Requirements

```json
{
  "capturePath": "/data/captures/test.cap",
  "bssid": "00:11:22:33:44:55",
  "essid": "TargetNetwork",
  "wordlist": "rockyou-mini",
  "keyType": "wpa",
  "maxRuntime": 300
}
```

1. `capturePath` must be `.cap` or `.pcap`.
2. `capturePath` must be within allowed capture directories.
3. `bssid` must match `XX:XX:XX:XX:XX:XX`.
4. `maxRuntime` must be `<= 600` seconds.

### Wordlists

1. `rockyou-mini`
2. `top-1000`
3. `common-passwords`

### Example Output

```json
{
  "bssid": "00:11:22:33:44:55",
  "essid": "TargetNetwork",
  "key_type": "wpa",
  "cracked": true,
  "key": "password123",
  "keys_tested": 12000,
  "runtime_seconds": 45,
  "status": "cracked"
}
```

### Security Notes

1. Capture path is constrained to approved directories.
2. No arbitrary command flags are accepted.
3. Output is sanitized to avoid host-path leakage.

## msfvenom Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/msfvenom-adapter.js`

### Whitelisted Payloads

1. `windows/meterpreter/reverse_tcp`
2. `windows/shell_reverse_tcp`
3. `linux/x86/meterpreter/reverse_tcp`
4. `linux/x64/shell_reverse_tcp`
5. `php/meterpreter/reverse_tcp`
6. `python/meterpreter/reverse_tcp`
7. `cmd/unix/reverse_bash`

### Whitelisted Formats

1. `exe`
2. `elf`
3. `raw`
4. `c`
5. `py`
6. `php`
7. `asp`
8. `aspx`
9. `jsp`
10. `war`
11. `ps1`
12. `sh`
13. `bash`

### Input Schema

```json
{
  "payload": "linux/x64/shell_reverse_tcp",
  "format": "elf",
  "lhost": "10.0.0.1",
  "lport": 4444,
  "encoder": "x86/shikata_ga_nai",
  "iterations": 2,
  "badchars": "\\x00"
}
```

### Example Output

```json
{
  "payload": "linux/x64/shell_reverse_tcp",
  "format": "elf",
  "size_bytes": 1024,
  "encoded": true,
  "encoder": "x86/shikata_ga_nai",
  "iterations": 2,
  "payload_data": "<base64>",
  "runtime_seconds": 2,
  "status": "generated"
}
```

### Security Warnings

1. Payload and format are strict-allowlist only.
2. Binary outputs are base64 encoded.
3. No dynamic payload construction beyond whitelisted values.

## ffuf Adapter

File: `/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/tools/adapters/ffuf-adapter.js`

### URL Fuzzing Syntax

`url` must include `FUZZ`, for example:

`http://target.example/FUZZ`

### Built-in Wordlists

1. `common`
2. `dirb-small`
3. `dirb-medium`
4. `params`
5. `subdomains`
6. `custom` (requires `customWords`)

### Input Schema

```json
{
  "url": "http://target.example/FUZZ",
  "wordlist": "common",
  "method": "GET",
  "threads": 10,
  "rate": 50,
  "matchCodes": [200, 301],
  "filterCodes": [404],
  "maxRuntime": 300
}
```

### Example Output

```json
{
  "url": "http://target.example/FUZZ",
  "total_requests": 5000,
  "successful_matches": 25,
  "results": [
    {
      "input": "admin",
      "url": "http://target.example/admin",
      "status": 200,
      "size": 1280,
      "words": 120,
      "lines": 40
    }
  ],
  "runtime_seconds": 120,
  "status": "completed"
}
```

### Responsible Use Guidelines

1. `threads` is capped at `50`.
2. `rate` is capped at `100` requests/second.
3. Runtime is capped at `600` seconds.
4. Use only on authorized targets.
