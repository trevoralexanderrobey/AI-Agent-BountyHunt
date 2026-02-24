const { exec } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");

const MAX_INLINE = 4000;
const MAX_STORED_BYTES = 50 * 1024 * 1024;
const MAX_CHUNK = 32000;
const MAX_SEARCH_RETURN_BYTES = 64 * 1024;
const DEFAULT_SEARCH_MAX_MATCHES = 50;
const MAX_SEARCH_MATCHES = 200;
const DEFAULT_CONTEXT_BEFORE = 3;
const DEFAULT_CONTEXT_AFTER = 3;
const MAX_CONTEXT_LINES = 20;

const JOBS_ROOT = path.join(os.homedir(), ".openclaw", "jobs");
const TOOL_NAME = "nmap";
const SKILL_SLUG = "nmap";

const SENSITIVE_PATTERNS = [
  /authorization:\s*.*/gi,
  /cookie:\s*.*/gi,
  /set-cookie:\s*.*/gi,
  /x-api-key:\s*.*/gi,
];

function safeError(code, message, details) {
  const payload = {
    ok: false,
    error: {
      code: String(code || "UNKNOWN_ERROR"),
      message: String(message || "Unexpected error"),
    },
  };

  if (typeof details !== "undefined") {
    payload.error.details = details;
  }

  return payload;
}

function makeFailure(code, message, details) {
  const error = new Error(String(message || "Unexpected error"));
  error.code = String(code || "UNKNOWN_ERROR");
  if (typeof details !== "undefined") {
    error.details = details;
  }
  return error;
}

function toSafeError(error, fallbackCode, fallbackMessage) {
  if (error && typeof error === "object" && typeof error.code === "string" && typeof error.message === "string") {
    return safeError(error.code, error.message, error.details);
  }
  const message = error instanceof Error ? error.message : String(error || fallbackMessage || "Unexpected error");
  return safeError(fallbackCode || "UNKNOWN_ERROR", message, error && error.details);
}

function asString(value) {
  return typeof value === "string" ? value : String(value || "");
}

function redactHeaders(input) {
  let redacted = asString(input);
  for (const pattern of SENSITIVE_PATTERNS) {
    redacted = redacted.replace(pattern, (match) => `${match.split(":")[0]}: <redacted>`);
  }
  return redacted;
}

function byteLengthUtf8(input) {
  return Buffer.byteLength(asString(input), "utf8");
}

function countLines(input) {
  const text = asString(input);
  if (!text) {
    return 0;
  }
  return text.split(/\r?\n/).length;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(asString(input), "utf8").digest("hex");
}

function randomHex(bytes = 3) {
  return crypto.randomBytes(bytes).toString("hex");
}

function createJobId() {
  return `${SKILL_SLUG}-${Date.now()}-${randomHex(3)}`;
}

function validateJobId(rawJobId) {
  const jobId = asString(rawJobId).trim();
  if (!jobId) {
    throw makeFailure("INVALID_JOB_ID", "job_id is required");
  }
  if (jobId.includes("..") || jobId.includes("/") || jobId.includes("\\")) {
    throw makeFailure("INVALID_JOB_ID", "job_id contains forbidden path characters");
  }
  if (!/^[A-Za-z0-9._-]+$/.test(jobId)) {
    throw makeFailure("INVALID_JOB_ID", "job_id must match /^[A-Za-z0-9._-]+$/");
  }
  return jobId;
}

function resolveJobDir(jobId) {
  const safeJobId = validateJobId(jobId);
  const rootPath = path.resolve(JOBS_ROOT);
  const jobPath = path.resolve(rootPath, safeJobId);
  if (!(jobPath === rootPath || jobPath.startsWith(`${rootPath}${path.sep}`))) {
    throw makeFailure("INVALID_JOB_ID", "Resolved job directory escapes jobs root");
  }
  return jobPath;
}

function normalizeStream(streamRaw) {
  const stream = asString(streamRaw || "stdout").trim().toLowerCase();
  if (stream !== "stdout" && stream !== "stderr") {
    throw makeFailure("INVALID_STREAM", "stream must be 'stdout' or 'stderr'");
  }
  return stream;
}

function resolveStreamPath(jobId, streamRaw) {
  const stream = normalizeStream(streamRaw);
  const jobDir = resolveJobDir(jobId);
  return {
    stream,
    filePath: path.join(jobDir, `${stream}.txt`),
    jobDir,
  };
}

function parseIntWithDefault(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function sliceByUtf8Bytes(input, maxBytes) {
  const text = asString(input);
  const budget = Math.max(0, Number(maxBytes) || 0);
  if (budget <= 0) {
    return "";
  }
  if (byteLengthUtf8(text) <= budget) {
    return text;
  }
  return Buffer.from(text, "utf8").subarray(0, budget).toString("utf8");
}

function buildCommand(args = {}) {
  const parts = ["docker", "run", "--rm"];
  const netFlag = "".trim();
  if (netFlag) {
    parts.push(netFlag);
  }

  parts.push("kali-rolling", TOOL_NAME);

  const defaultFlags = "".trim();
  if (defaultFlags) {
    parts.push(defaultFlags);
  }

  const runtimeFlags = typeof args.flags === "string" ? args.flags.trim() : "";
  if (runtimeFlags) {
    parts.push(runtimeFlags);
  }

  const target = typeof args.target === "string" ? args.target.trim() : "";
  if (target) {
    parts.push(target);
  }

  return parts.join(" ");
}

function executeCommand(command, maxBufferBytes) {
  return new Promise((resolve) => {
    exec(command, { maxBuffer: maxBufferBytes }, (error, stdout, stderr) => {
      resolve({
        error,
        stdout: asString(stdout),
        stderr: asString(stderr),
      });
    });
  });
}

async function writeStoredOutputs(jobId, redactedStdout, redactedStderr, executionMeta) {
  const jobDir = resolveJobDir(jobId);
  await fsp.mkdir(jobDir, { recursive: true });

  const fullStdoutBytes = byteLengthUtf8(redactedStdout);
  const fullStderrBytes = byteLengthUtf8(redactedStderr);
  const totalRedactedBytes = fullStdoutBytes + fullStderrBytes;

  let storedStdout = redactedStdout;
  let storedStderr = redactedStderr;
  let truncatedByStorageCap = false;

  if (totalRedactedBytes > MAX_STORED_BYTES) {
    truncatedByStorageCap = true;
    let budget = MAX_STORED_BYTES;
    storedStdout = sliceByUtf8Bytes(redactedStdout, budget);
    budget -= byteLengthUtf8(storedStdout);
    storedStderr = sliceByUtf8Bytes(redactedStderr, budget);
  }

  const storedStdoutBytes = byteLengthUtf8(storedStdout);
  const storedStderrBytes = byteLengthUtf8(storedStderr);
  const storedRedactedBytes = storedStdoutBytes + storedStderrBytes;

  const stdoutPath = path.join(jobDir, "stdout.txt");
  const stderrPath = path.join(jobDir, "stderr.txt");
  const metaPath = path.join(jobDir, "meta.json");

  const meta = {
    job_id: jobId,
    slug: SKILL_SLUG,
    byte_length_stdout: fullStdoutBytes,
    byte_length_stderr: fullStderrBytes,
    line_count_stdout: countLines(redactedStdout),
    line_count_stderr: countLines(redactedStderr),
    sha256_stdout: sha256Hex(redactedStdout),
    sha256_stderr: sha256Hex(redactedStderr),
    created_at_epoch_ms: Date.now(),
    exit_code: executionMeta.exitCode,
    signal: executionMeta.signal,
    command_executed: executionMeta.command,
    total_redacted_bytes: totalRedactedBytes,
    stored_redacted_bytes: storedRedactedBytes,
    truncated_by_storage_cap: truncatedByStorageCap,
    storage_cap_bytes: MAX_STORED_BYTES,
  };

  await fsp.writeFile(stdoutPath, storedStdout, "utf8");
  await fsp.writeFile(stderrPath, storedStderr, "utf8");
  await fsp.writeFile(metaPath, JSON.stringify(meta, null, 2), "utf8");

  return {
    meta,
    truncatedByStorageCap,
  };
}

async function buildExecutionResponse(command, commandResult) {
  const redactedStdout = redactHeaders(commandResult.stdout);
  const redactedStderr = redactHeaders(commandResult.stderr);

  const stdoutBytes = byteLengthUtf8(redactedStdout);
  const stderrBytes = byteLengthUtf8(redactedStderr);
  const totalBytes = stdoutBytes + stderrBytes;
  const totalLineCount = countLines(redactedStdout) + countLines(redactedStderr);

  const commandFailed = Boolean(commandResult.error);
  const exitCode =
    commandFailed && Number.isFinite(Number(commandResult.error.code))
      ? Number(commandResult.error.code)
      : commandFailed
        ? null
        : 0;
  const signal = commandFailed && typeof commandResult.error.signal === "string" ? commandResult.error.signal : null;

  const basePayload = {
    mode: "headless-kali",
    tool: TOOL_NAME,
    command,
    exit_code: exitCode,
    signal,
    byte_length: totalBytes,
    line_count: totalLineCount,
  };

  if (totalBytes <= MAX_INLINE) {
    const inlinePayload = {
      ...basePayload,
      truncated: false,
      retrieval_available: false,
      stdout: redactedStdout,
      stderr: redactedStderr,
    };

    if (commandFailed) {
      return {
        ...inlinePayload,
        ...safeError("COMMAND_EXEC_FAILED", commandResult.error.message || "Command execution failed"),
      };
    }

    return {
      ok: true,
      ...inlinePayload,
    };
  }

  const jobId = createJobId();
  const persisted = await writeStoredOutputs(jobId, redactedStdout, redactedStderr, {
    command,
    exitCode,
    signal,
  });

  const storedPayload = {
    ...basePayload,
    truncated: true,
    job_id: jobId,
    stdout_preview: redactedStdout.slice(0, 2000),
    stdout_tail: redactedStdout.slice(-2000),
    stderr_preview: redactedStderr.slice(0, 1000),
    retrieval_available: true,
    note: "Full output stored. Use nmap_read_output_chunk or nmap_search_output.",
  };

  if (persisted.truncatedByStorageCap) {
    storedPayload.storage_capped = true;
  }

  if (commandFailed) {
    return {
      ...storedPayload,
      ...safeError("COMMAND_EXEC_FAILED", commandResult.error.message || "Command execution failed"),
    };
  }

  return {
    ok: true,
    ...storedPayload,
  };
}

async function ensureReadableFile(filePath) {
  try {
    await fsp.access(filePath, fs.constants.R_OK);
  } catch {
    throw makeFailure("NOT_FOUND", `File not found or unreadable: ${filePath}`);
  }
}

async function readOutputChunk(args = {}) {
  const jobId = validateJobId(args.job_id);
  const offset = Math.max(0, parseIntWithDefault(args.offset, 0));
  const requestedLength = Math.max(0, parseIntWithDefault(args.length, 4000));
  const effectiveLength = Math.min(requestedLength, MAX_CHUNK);

  const resolved = resolveStreamPath(jobId, args.stream || "stdout");
  await ensureReadableFile(resolved.filePath);

  const text = await fsp.readFile(resolved.filePath, "utf8");
  const boundedOffset = Math.min(offset, text.length);
  const boundedEnd = Math.min(boundedOffset + effectiveLength, text.length);
  const chunk = text.slice(boundedOffset, boundedEnd);

  return {
    ok: true,
    job_id: jobId,
    stream: resolved.stream,
    offset: boundedOffset,
    requested_length: requestedLength,
    length: effectiveLength,
    chunk_length: chunk.length,
    total_length: text.length,
    chunk,
  };
}

function computeSearchPayloadBytes(jobId, stream, matches, totalMatches, truncatedMatches, maxMatches, contextBefore, contextAfter) {
  return byteLengthUtf8(
    JSON.stringify({
      ok: true,
      job_id: jobId,
      stream,
      total_matches: totalMatches,
      truncated_matches: truncatedMatches,
      max_matches: maxMatches,
      context_before: contextBefore,
      context_after: contextAfter,
      matches,
    }),
  );
}

async function searchOutput(args = {}) {
  const jobId = validateJobId(args.job_id);
  const pattern = asString(args.pattern).trim();
  if (!pattern) {
    throw makeFailure("INVALID_PATTERN", "pattern is required");
  }

  const regexFlags = typeof args.flags === "string" ? args.flags : "";
  let regex;
  try {
    regex = new RegExp(pattern, regexFlags);
  } catch (error) {
    throw makeFailure("INVALID_REGEX", error.message || "Invalid regular expression");
  }

  const maxMatches = clamp(parseIntWithDefault(args.max_matches, DEFAULT_SEARCH_MAX_MATCHES), 1, MAX_SEARCH_MATCHES);
  const contextBefore = clamp(parseIntWithDefault(args.context_before, DEFAULT_CONTEXT_BEFORE), 0, MAX_CONTEXT_LINES);
  const contextAfter = clamp(parseIntWithDefault(args.context_after, DEFAULT_CONTEXT_AFTER), 0, MAX_CONTEXT_LINES);

  const resolved = resolveStreamPath(jobId, args.stream || "stdout");
  await ensureReadableFile(resolved.filePath);

  const matches = [];
  let totalMatches = 0;
  let truncatedMatches = false;
  let allowNewMatches = true;
  let allowContextGrowth = true;
  const beforeBuffer = [];
  const pendingAfter = [];
  let lineNumber = 0;

  const input = fs.createReadStream(resolved.filePath, { encoding: "utf8" });
  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  for await (const line of rl) {
    lineNumber += 1;
    const lineText = asString(line);

    if (allowContextGrowth && pendingAfter.length > 0) {
      for (let i = pendingAfter.length - 1; i >= 0; i -= 1) {
        const pending = pendingAfter[i];
        if (pending.remaining > 0) {
          pending.entry.context_after_lines.push({
            line_number: lineNumber,
            line: lineText,
          });
          pending.remaining -= 1;

          const payloadBytes = computeSearchPayloadBytes(
            jobId,
            resolved.stream,
            matches,
            totalMatches,
            truncatedMatches,
            maxMatches,
            contextBefore,
            contextAfter,
          );
          if (payloadBytes > MAX_SEARCH_RETURN_BYTES) {
            pending.entry.context_after_lines.pop();
            pending.remaining = 0;
            allowContextGrowth = false;
            allowNewMatches = false;
            truncatedMatches = true;
          }
        }

        if (pending.remaining <= 0) {
          pendingAfter.splice(i, 1);
        }
      }
    }

    regex.lastIndex = 0;
    if (regex.test(lineText)) {
      totalMatches += 1;
      if (allowNewMatches) {
        if (matches.length >= maxMatches) {
          allowNewMatches = false;
          truncatedMatches = true;
        } else {
          const entry = {
            line_number: lineNumber,
            line: lineText,
            context_before_lines: beforeBuffer.slice(),
            context_after_lines: [],
          };
          matches.push(entry);

          const payloadBytes = computeSearchPayloadBytes(
            jobId,
            resolved.stream,
            matches,
            totalMatches,
            truncatedMatches,
            maxMatches,
            contextBefore,
            contextAfter,
          );
          if (payloadBytes > MAX_SEARCH_RETURN_BYTES) {
            matches.pop();
            allowNewMatches = false;
            allowContextGrowth = false;
            truncatedMatches = true;
          } else if (contextAfter > 0 && allowContextGrowth) {
            pendingAfter.push({
              entry,
              remaining: contextAfter,
            });
          }
        }
      }
    }

    if (contextBefore > 0) {
      beforeBuffer.push({
        line_number: lineNumber,
        line: lineText,
      });
      if (beforeBuffer.length > contextBefore) {
        beforeBuffer.shift();
      }
    }
  }

  while (
    matches.length > 0 &&
    computeSearchPayloadBytes(
      jobId,
      resolved.stream,
      matches,
      totalMatches,
      truncatedMatches,
      maxMatches,
      contextBefore,
      contextAfter,
    ) > MAX_SEARCH_RETURN_BYTES
  ) {
    matches.pop();
    truncatedMatches = true;
  }

  return {
    ok: true,
    job_id: jobId,
    stream: resolved.stream,
    total_matches: totalMatches,
    max_matches: maxMatches,
    context_before: contextBefore,
    context_after: contextAfter,
    truncated_matches: truncatedMatches,
    matches,
    search_return_cap_bytes: MAX_SEARCH_RETURN_BYTES,
    search_return_bytes: computeSearchPayloadBytes(
      jobId,
      resolved.stream,
      matches,
      totalMatches,
      truncatedMatches,
      maxMatches,
      contextBefore,
      contextAfter,
    ),
  };
}

async function readOutputMeta(args = {}) {
  const jobId = validateJobId(args.job_id);
  const jobDir = resolveJobDir(jobId);
  const metaPath = path.join(jobDir, "meta.json");
  await ensureReadableFile(metaPath);

  let parsed;
  try {
    parsed = JSON.parse(await fsp.readFile(metaPath, "utf8"));
  } catch (error) {
    throw makeFailure("INVALID_META", error.message || "meta.json is not valid JSON");
  }

  return {
    ok: true,
    job_id: jobId,
    meta: parsed,
  };
}

module.exports = {
  async nmap_run(args = {}) {
    try {
      const command = buildCommand(args);
      const commandResult = await executeCommand(command, 8 * 1024 * 1024);
      return await buildExecutionResponse(command, commandResult);
    } catch (error) {
      return toSafeError(error, "RUN_FAILED", "Failed to execute tool");
    }
  },

  async nmap_health(args = {}) {
    try {
      const netFlag = "".trim();
      const command = `docker run --rm ${netFlag} kali-rolling nmap --version`.trim();
      const commandResult = await executeCommand(command, 2 * 1024 * 1024);
      return await buildExecutionResponse(command, commandResult);
    } catch (error) {
      return toSafeError(error, "HEALTH_FAILED", "Health check failed");
    }
  },

  async nmap_read_output_chunk(args = {}) {
    try {
      return await readOutputChunk(args);
    } catch (error) {
      return toSafeError(error, "READ_OUTPUT_CHUNK_FAILED", "Failed to read output chunk");
    }
  },

  async nmap_search_output(args = {}) {
    try {
      return await searchOutput(args);
    } catch (error) {
      return toSafeError(error, "SEARCH_OUTPUT_FAILED", "Failed to search output");
    }
  },

  async nmap_output_meta(args = {}) {
    try {
      return await readOutputMeta(args);
    } catch (error) {
      return toSafeError(error, "OUTPUT_META_FAILED", "Failed to read output metadata");
    }
  },
};