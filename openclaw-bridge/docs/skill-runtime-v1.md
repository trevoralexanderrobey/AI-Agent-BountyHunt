# Skill Runtime v1

This document freezes the current CLI skill runtime contract used by generated `tools.js` modules.

## Naming and Export Pattern

Generated CLI skills export methods with the format `<slug>_<method>`.

Runtime v1 method set:

- Control: `run`, `health`
- Forensics: `read_output_chunk`, `search_output`
- Indexing: `semantic_summary`
- Intelligence: `anomaly_summary`, `anomaly_diff`
- Baseline: `tag_baseline`, `list_baselines`, `diff_against_baseline`
- Compatibility: `output_meta`, `semantic_diff`

## Shared Guarantees

- Structured errors: all methods return `{ ok: false, error: { code, message, details? } }` on failure.
- Job ID safety: `job_id` values are rejected if empty, contain `..`, `/`, `\\`, or fail `^[A-Za-z0-9._-]+$`.
- Determinism: sorting and tie-break rules are deterministic where arrays/maps are returned.
- No uncaught exceptions are surfaced to callers.

## File Artifact Model

Runtime v1 uses:

- Job root: `~/.openclaw/jobs/<job_id>/`
- Job artifacts:
  - `stdout.txt`
  - `stderr.txt`
  - `meta.json`
  - `semantic.json`
  - `anomalies.json`
- Tool baseline root: `~/.openclaw/tools/<slug>/`
- Baseline artifact:
  - `baselines.json`

---

## Control

### `run(args = {})`

Input:

- `args.flags?: string | string[]`
- `args.target?: string | string[]`

Output (inline path, redacted aggregate UTF-8 bytes `<= 4000`):

- `{ ok: true, mode, tool, command, exit_code, signal, byte_length, line_count, truncated: false, retrieval_available: false, stdout, stderr }`
- If command failed, returns same payload with `ok:false,error` merged.

Output (stored path, aggregate UTF-8 bytes `> 4000`):

- `{ ok: true, mode, tool, command, exit_code, signal, byte_length, line_count, truncated: true, job_id, stdout_preview, stdout_tail, stderr_preview, retrieval_available: true, note, semantic_available, semantic_summary_preview?, anomaly_score, anomaly_preview, storage_capped? }`
- If command failed, returns same payload with `ok:false,error` merged.

Side effects:

- Executes Docker command via `spawn("docker", [...])`.
- May write `stdout.txt`, `stderr.txt`, `meta.json`.
- May write `semantic.json` and `anomalies.json` (non-blocking for main run result).

Primary internal error codes:

- `INVALID_ARGUMENT_TYPE`, `DOCKER_NOT_FOUND`, `SPAWN_FAILED`, `MAX_BUFFER_EXCEEDED`, `COMMAND_EXEC_FAILED`
- Fallback wrapper code: `RUN_FAILED`

Determinism:

- Header redaction is deterministic.
- Storage cap and preview/tail logic deterministic for same redacted output.
- Semantic/anomaly outputs deterministic for same stored content.

### `health(args = {})`

Input:

- Ignored object.

Behavior:

- Executes `docker run --rm [--net=host] kali-rolling <tool> --version`.
- Reuses same response model as `run()` (including inline vs stored behavior).

Side effects:

- Same conditional storage side effects as `run()` if output exceeds inline threshold.

Primary internal error codes:

- `DOCKER_NOT_FOUND`, `SPAWN_FAILED`, `MAX_BUFFER_EXCEEDED`, `COMMAND_EXEC_FAILED`
- Fallback wrapper code: `HEALTH_FAILED`

---

## Forensics

### `read_output_chunk(args = {})`

Input:

- `job_id: string` (required)
- `stream?: "stdout" | "stderr"` (default `"stdout"`)
- `offset?: number` (default `0`, min `0`)
- `length?: number` (default `4000`, clamped max `32000`)

Output:

- `{ ok: true, job_id, stream, offset, requested_length, length, chunk_length, total_length, chunk }`

Side effects:

- Read-only access to `<job_dir>/<stream>.txt`.

Error codes:

- `INVALID_JOB_ID`, `INVALID_STREAM`, `NOT_FOUND`
- Fallback wrapper code: `READ_OUTPUT_CHUNK_FAILED`

Determinism:

- Same file + same args returns same chunk payload.

### `search_output(args = {})`

Input:

- `job_id: string` (required)
- `pattern: string` (required)
- `flags?: string` (regex flags)
- `stream?: "stdout" | "stderr"` (default `"stdout"`)
- `max_matches?: number` (default `50`, clamp `1..200`)
- `context_before?: number` (default `3`, clamp `0..20`)
- `context_after?: number` (default `3`, clamp `0..20`)

Output:

- `{ ok: true, job_id, stream, total_matches, max_matches, context_before, context_after, truncated_matches, matches, search_return_cap_bytes, search_return_bytes }`

Behavior:

- Line-by-line regex scan with context windows.
- Enforces global response cap of `64KB` serialized JSON.

Side effects:

- Read-only stream read of `<job_dir>/<stream>.txt`.

Error codes:

- `INVALID_JOB_ID`, `INVALID_PATTERN`, `INVALID_REGEX`, `INVALID_STREAM`, `NOT_FOUND`
- Fallback wrapper code: `SEARCH_OUTPUT_FAILED`

Determinism:

- Deterministic for same file content, args, and regex engine behavior.

---

## Indexing

### `semantic_summary(args = {})`

Input:

- `job_id: string` (required)

Output:

- `{ ok: true, job_id, semantic }` where `semantic` is parsed `semantic.json`.

Side effects:

- Read-only access to `<job_dir>/semantic.json`.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_SEMANTIC`
- Fallback wrapper code: `SEMANTIC_SUMMARY_FAILED`

Determinism:

- Deterministic read/parse of persisted artifact.

---

## Intelligence

### `anomaly_summary(args = {})`

Input:

- `job_id: string` (required)

Output:

- `{ ok: true, job_id, anomalies }` where `anomalies` is parsed `anomalies.json`.

Side effects:

- Read-only access to `<job_dir>/anomalies.json`.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_ANOMALY`
- Fallback wrapper code: `ANOMALY_SUMMARY_FAILED`

### `anomaly_diff(args = {})`

Input:

- `base_job_id: string` (required)
- `compare_job_id: string` (required)

Output:

- `{ ok: true, base_job_id, compare_job_id, score_delta, severity_change, new_anomalies, resolved_anomalies, persistent_anomalies }`

Identity guard:

- If `base_job_id === compare_job_id`, returns unchanged delta with persistent anomalies from that single artifact.

Side effects:

- Read-only access to involved `anomalies.json` files.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_ANOMALY`
- Fallback wrapper code: `ANOMALY_DIFF_FAILED`

Determinism:

- Type arrays are normalized/sorted alphabetically.
- Score delta rounded to 4 decimals.

---

## Baseline

### `tag_baseline(args = {})`

Input:

- `job_id: string` (required)
- `tag: string` (required, regex `^[A-Za-z0-9-]+$`, case preserved)

Behavior:

- Validates `job_id` and requires readable `<job_dir>/meta.json`.
- Reads existing `baselines.json` or initializes empty if missing.
- Overwrites existing mapping for same tag.
- Persists atomically (temp file in same dir then `rename`).

Output:

- `{ ok: true, job_id, tag }`

Side effects:

- Creates `~/.openclaw/tools/<slug>/` if needed.
- Writes `~/.openclaw/tools/<slug>/baselines.json` atomically.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_TAG`, `INVALID_BASELINES`, `INVALID_BASELINE_PATH`
- Fallback wrapper code: `TAG_BASELINE_FAILED`

Determinism:

- Tag keys sorted alphabetically before write.

### `list_baselines(args = {})`

Input:

- ignored object

Output:

- If missing file: `{ ok: true, baselines: { tags: {} } }`
- Else: `{ ok: true, baselines: { tags: <sorted map> } }`

Behavior:

- Does not auto-repair malformed files.

Side effects:

- Read-only unless directory already exists from previous operations.

Error codes:

- `INVALID_BASELINES`, `INVALID_BASELINE_PATH`
- Fallback wrapper code: `LIST_BASELINES_FAILED`

### `diff_against_baseline(args = {})`

Input:

- `job_id: string` (required)
- `tag: string` (required)

Behavior:

- Validates compare `job_id` + compare `meta.json` existence.
- Validates `tag`.
- Reads `baselines.json` and resolves `base_job_id` by tag.
- Delegates directly to `readAnomalyDiff({ base_job_id, compare_job_id: job_id })` and returns payload unchanged.

Output:

- Same output shape as `anomaly_diff()`.

Side effects:

- Read-only baseline + anomaly reads.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_TAG`, `INVALID_BASELINES`, `BASELINE_TAG_NOT_FOUND`, `INVALID_ANOMALY`
- Fallback wrapper code: `DIFF_AGAINST_BASELINE_FAILED`

Determinism:

- Inherits anomaly diff determinism and identity guard behavior.

---

## Compatibility Methods

### `output_meta(args = {})`

Input:

- `job_id: string` (required)

Output:

- `{ ok: true, job_id, meta }` parsed from `meta.json`.

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_META`
- Fallback wrapper code: `OUTPUT_META_FAILED`

### `semantic_diff(args = {})`

Input:

- `base_job_id: string`
- `compare_job_id: string`

Output:

- `{ ok: true, base_job_id, compare_job_id, new_error_signatures, removed_error_signatures, changed_error_counts, stack_trace_delta, high_entropy_delta }`

Error codes:

- `INVALID_JOB_ID`, `NOT_FOUND`, `INVALID_SEMANTIC`
- Fallback wrapper code: `SEMANTIC_DIFF_FAILED`
