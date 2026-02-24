const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");

function createSkillRuntime(config = {}) {
  const MAX_INLINE = 4000;
  const MAX_STORED_BYTES = 50 * 1024 * 1024;
  const MAX_CHUNK = 32000;
  const MAX_SEARCH_RETURN_BYTES = 64 * 1024;
  const DEFAULT_SEARCH_MAX_MATCHES = 50;
  const MAX_SEARCH_MATCHES = 200;
  const DEFAULT_CONTEXT_BEFORE = 3;
  const DEFAULT_CONTEXT_AFTER = 3;
  const MAX_CONTEXT_LINES = 20;
  const SEMANTIC_DEDUP_THRESHOLD = 5;
  const SEMANTIC_HIGH_ENTROPY_THRESHOLD = 4.5;
  const SEMANTIC_HIGH_ENTROPY_LIMIT = 20;
  const SEMANTIC_SNIPPET_MAX_CHARS = 200;

  const JOBS_ROOT = path.join(os.homedir(), ".openclaw", "jobs");
  const TOOLS_ROOT = path.join(os.homedir(), ".openclaw", "tools");
  const TOOL_NAME = asString(config.toolName);
  const SKILL_SLUG = asString(config.slug);
  const INJECT_HOST_NET = Boolean(config.injectHostNet);
  const DEFAULT_FLAGS_VALUE = typeof config.defaultFlags === "string" ? config.defaultFlags : asString(config.defaultFlags);

  const SENSITIVE_PATTERNS = [
    /authorization:\s*.*/gi,
    /cookie:\s*.*/gi,
    /set-cookie:\s*.*/gi,
    /x-api-key:\s*.*/gi,
  ];
  const ERROR_LIKE_REGEX = /\b(error|exception|failed|panic)\b/i;

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

  function resolveToolBaselinesDir() {
    const rootPath = path.resolve(TOOLS_ROOT);
    const toolPath = path.resolve(rootPath, SKILL_SLUG);
    if (!(toolPath === rootPath || toolPath.startsWith(`${rootPath}${path.sep}`))) {
      throw makeFailure("INVALID_BASELINE_PATH", "Resolved baseline directory escapes tools root");
    }
    return toolPath;
  }

  function resolveToolBaselinesPath() {
    const toolDir = resolveToolBaselinesDir();
    const baselinePath = path.resolve(toolDir, "baselines.json");
    if (!(baselinePath === toolDir || baselinePath.startsWith(`${toolDir}${path.sep}`))) {
      throw makeFailure("INVALID_BASELINE_PATH", "Resolved baseline file escapes tool baseline directory");
    }
    return baselinePath;
  }

  function validateBaselineTag(rawTag) {
    const tag = asString(rawTag).trim();
    if (!tag) {
      throw makeFailure("INVALID_TAG", "tag is required");
    }
    if (!/^[A-Za-z0-9-]+$/.test(tag)) {
      throw makeFailure("INVALID_TAG", "tag must match /^[A-Za-z0-9-]+$/");
    }
    return tag;
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

  function splitArgInput(value, fieldName) {
    if (typeof value === "undefined" || value === null) {
      return [];
    }

    if (typeof value === "string") {
      const trimmed = value.trim();
      return trimmed ? trimmed.split(/\s+/).filter(Boolean) : [];
    }

    if (Array.isArray(value)) {
      const out = [];
      for (const item of value) {
        if (typeof item !== "string") {
          throw makeFailure("INVALID_ARGUMENT_TYPE", `${fieldName} array must contain only strings`);
        }
        const trimmed = item.trim();
        if (trimmed) {
          out.push(trimmed);
        }
      }
      return out;
    }

    throw makeFailure("INVALID_ARGUMENT_TYPE", `${fieldName} must be a string or array of strings`);
  }

  function splitLines(input) {
    const text = asString(input);
    if (!text) {
      return [];
    }
    return text.split(/\r?\n/);
  }

  function normalizeSemanticLine(input) {
    let normalized = asString(input);
    normalized = normalized.replace(/\b\d{4}-\d{2}-\d{2}(?:[Tt ][0-9:.+-Zz]+)?\b/g, " ");
    normalized = normalized.replace(/\b0x[0-9a-fA-F]+\b/g, " ");
    normalized = normalized.replace(/\b\d+\b/g, " ");
    normalized = normalized.replace(/\s+/g, " ").trim().toLowerCase();
    return normalized;
  }

  function shannonEntropy(input) {
    const text = asString(input);
    if (!text) {
      return 0;
    }

    const frequencies = new Map();
    for (const char of text) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    const total = text.length;
    for (const count of frequencies.values()) {
      const probability = count / total;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  function isStackTraceLine(input) {
    const text = asString(input);
    return /^Traceback/.test(text) || /^Exception/.test(text) || /^panic:/.test(text) || /^\s+at\s+/.test(text);
  }

  function buildSemanticAnalysis(redactedStdout, redactedStderr) {
    const lines = [...splitLines(redactedStdout), ...splitLines(redactedStderr)];
    const errorClusters = new Map();
    const exactLineCounts = new Map();
    const normalizedPatternHashes = new Set();
    const highEntropyLines = [];

    let errorLikeLines = 0;
    let stackTraceBlocks = 0;
    let inStackTraceBlock = false;

    for (let index = 0; index < lines.length; index += 1) {
      const line = asString(lines[index]);
      const lineNumber = index + 1;

      const normalized = normalizeSemanticLine(line);
      const normalizedHash = sha256Hex(normalized);
      normalizedPatternHashes.add(normalizedHash);

      if (line.trim()) {
        exactLineCounts.set(line, (exactLineCounts.get(line) || 0) + 1);
      }

      if (ERROR_LIKE_REGEX.test(line)) {
        errorLikeLines += 1;
        const existing = errorClusters.get(normalizedHash);
        if (existing) {
          existing.count += 1;
        } else {
          errorClusters.set(normalizedHash, {
            signature: normalized,
            normalized_hash: normalizedHash,
            count: 1,
            sample: line,
          });
        }
      }

      const isTraceLine = isStackTraceLine(line);
      if (isTraceLine && !inStackTraceBlock) {
        stackTraceBlocks += 1;
      }
      inStackTraceBlock = isTraceLine;

      if (highEntropyLines.length < SEMANTIC_HIGH_ENTROPY_LIMIT && line.length > 20) {
        const entropy = shannonEntropy(line);
        if (entropy > SEMANTIC_HIGH_ENTROPY_THRESHOLD) {
          highEntropyLines.push({
            line_number: lineNumber,
            entropy: Number(entropy.toFixed(4)),
            snippet: line.slice(0, SEMANTIC_SNIPPET_MAX_CHARS),
          });
        }
      }
    }

    const clusteredErrors = Array.from(errorClusters.values()).sort(
      (left, right) => (right.count - left.count) || left.signature.localeCompare(right.signature),
    );
    const deduplicatedLines = Array.from(exactLineCounts.entries())
      .filter(([, count]) => count > SEMANTIC_DEDUP_THRESHOLD)
      .map(([text, count]) => ({
        text,
        count,
      }))
      .sort((left, right) => (right.count - left.count) || left.text.localeCompare(right.text));

    return {
      error_clusters: clusteredErrors,
      deduplicated_lines: deduplicatedLines,
      stack_traces_detected: stackTraceBlocks,
      high_entropy_lines: highEntropyLines,
      summary_metrics: {
        total_lines: lines.length,
        unique_normalized_patterns: normalizedPatternHashes.size,
        error_like_lines: errorLikeLines,
      },
    };
  }

  function buildDockerInvocation(args = {}) {
    const defaultFlags = splitArgInput(DEFAULT_FLAGS_VALUE, "default_flags");
    const runtimeFlags = splitArgInput(args.flags, "flags");
    const targetArgs = splitArgInput(args.target, "target");

    const commandArgs = [
      "run",
      "--rm",
      ...(INJECT_HOST_NET ? ["--net=host"] : []),
      "kali-rolling",
      TOOL_NAME,
      ...defaultFlags,
      ...runtimeFlags,
      ...targetArgs,
    ];

    return {
      command: "docker",
      commandArgs,
      commandDisplay: ["docker", ...commandArgs].join(" "),
    };
  }

  function buildHealthInvocation() {
    const commandArgs = [
      "run",
      "--rm",
      ...(INJECT_HOST_NET ? ["--net=host"] : []),
      "kali-rolling",
      TOOL_NAME,
      "--version",
    ];
    return {
      command: "docker",
      commandArgs,
      commandDisplay: ["docker", ...commandArgs].join(" "),
    };
  }

  function executeCommand(command, commandArgs, maxBufferBytes) {
    return new Promise((resolve) => {
      const stdoutChunks = [];
      const stderrChunks = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let settled = false;
      let spawnError = null;
      let didExceedBuffer = false;

      const finish = (payload) => {
        if (!settled) {
          settled = true;
          resolve(payload);
        }
      };

      let child;
      try {
        child = spawn(command, commandArgs);
      } catch (error) {
        finish({
          error: makeFailure("SPAWN_FAILED", error instanceof Error ? error.message : String(error)),
          stdout: "",
          stderr: "",
          exitCode: null,
          signal: null,
        });
        return;
      }

      const terminateForBuffer = () => {
        if (child && !child.killed) {
          try {
            child.kill("SIGTERM");
          } catch {
            // noop
          }
        }
      };

      child.on("error", (error) => {
        if (error && error.code === "ENOENT") {
          finish({
            error: makeFailure("DOCKER_NOT_FOUND", "docker binary not found on PATH"),
            stdout: "",
            stderr: "",
            exitCode: null,
            signal: null,
          });
          return;
        }
        spawnError = makeFailure("SPAWN_FAILED", error instanceof Error ? error.message : String(error));
      });

      child.stdout.on("data", (chunk) => {
        if (didExceedBuffer) {
          return;
        }
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
        stdoutBytes += buf.length;
        if (stdoutBytes + stderrBytes > maxBufferBytes) {
          didExceedBuffer = true;
          spawnError = makeFailure("MAX_BUFFER_EXCEEDED", "stdout maxBuffer length exceeded");
          terminateForBuffer();
          return;
        }
        stdoutChunks.push(buf);
      });

      child.stderr.on("data", (chunk) => {
        if (didExceedBuffer) {
          return;
        }
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
        stderrBytes += buf.length;
        if (stdoutBytes + stderrBytes > maxBufferBytes) {
          didExceedBuffer = true;
          spawnError = makeFailure("MAX_BUFFER_EXCEEDED", "stdout maxBuffer length exceeded");
          terminateForBuffer();
          return;
        }
        stderrChunks.push(buf);
      });

      child.on("close", (code, signal) => {
        const stdout = Buffer.concat(stdoutChunks).toString("utf8");
        const stderr = Buffer.concat(stderrChunks).toString("utf8");

        let error = spawnError;
        if (!error && code !== 0) {
          error = makeFailure(
            "COMMAND_EXEC_FAILED",
            `Command failed: ${[command, ...commandArgs].join(" ")}${stderr ? `\n${stderr}` : ""}`,
          );
        }

        finish({
          error: error || null,
          stdout,
          stderr,
          exitCode: Number.isFinite(Number(code)) ? Number(code) : null,
          signal: typeof signal === "string" ? signal : null,
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
      jobDir,
      meta,
      truncatedByStorageCap,
    };
  }

  async function writeSemanticFile(jobDir, semanticPayload) {
    const semanticPath = path.join(jobDir, "semantic.json");
    await fsp.writeFile(semanticPath, JSON.stringify(semanticPayload, null, 2), "utf8");
  }

  async function writeAnomalyFile(jobDir, anomalyPayload) {
    const anomalyPath = path.join(jobDir, "anomalies.json");
    await fsp.writeFile(anomalyPath, JSON.stringify(anomalyPayload, null, 2), "utf8");
  }

  function normalizeSemanticErrorClusters(semanticPayload) {
    const clusters = Array.isArray(semanticPayload?.error_clusters) ? semanticPayload.error_clusters : [];
    const aggregated = new Map();

    for (const cluster of clusters) {
      if (!cluster || typeof cluster !== "object") {
        continue;
      }
      const signature = asString(cluster.signature || cluster.normalized_hash).trim();
      if (!signature) {
        continue;
      }
      const count = Number.isFinite(Number(cluster.count)) ? Math.max(0, Number(cluster.count)) : 0;
      aggregated.set(signature, (aggregated.get(signature) || 0) + count);
    }

    return Array.from(aggregated.entries())
      .map(([signature, count]) => ({
        signature,
        count,
      }))
      .sort((left, right) => left.signature.localeCompare(right.signature));
  }

  function semanticErrorLikeLines(semanticPayload) {
    const value = semanticPayload?.summary_metrics?.error_like_lines;
    return Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
  }

  function semanticHighEntropyLineNumbers(semanticPayload) {
    const lines = Array.isArray(semanticPayload?.high_entropy_lines) ? semanticPayload.high_entropy_lines : [];
    const out = [];

    for (const item of lines) {
      const lineNumber = Number(item?.line_number);
      if (Number.isFinite(lineNumber)) {
        out.push(lineNumber);
      }
    }

    return Array.from(new Set(out)).sort((left, right) => left - right);
  }

  function computeAnomalyScore(anomalies) {
    const types = new Set((Array.isArray(anomalies) ? anomalies : []).map((entry) => asString(entry?.type)));
    let score = 0;

    if (types.has("dominant_error_cluster")) {
      score += 0.4;
    }
    if (types.has("rare_error_signature")) {
      score += 0.3;
    }
    if (types.has("isolated_high_entropy_line")) {
      score += 0.2;
    }

    return Number(Math.min(1, score).toFixed(4));
  }

  function extractAnomaliesFromSemantic(semanticPayload) {
    const anomalies = [];
    const clusters = normalizeSemanticErrorClusters(semanticPayload);
    const errorLikeLines = semanticErrorLikeLines(semanticPayload);

    if (errorLikeLines > 0 && clusters.length > 0) {
      const dominantCluster = [...clusters].sort((left, right) => (right.count - left.count) || left.signature.localeCompare(right.signature))[0];
      const dominantPercentage = dominantCluster.count / errorLikeLines;
      if (dominantPercentage > 0.5) {
        anomalies.push({
          type: "dominant_error_cluster",
          details: {
            signature: dominantCluster.signature,
            count: dominantCluster.count,
            percentage: Number(dominantPercentage.toFixed(4)),
          },
        });
      }
    }

    const rareClusters = clusters.filter((cluster) => cluster.count === 1);
    if (rareClusters.length > 0) {
      anomalies.push({
        type: "rare_error_signature",
        details: {
          signature: rareClusters[0].signature,
        },
      });
    }

    const highEntropyLines = Array.isArray(semanticPayload?.high_entropy_lines) ? semanticPayload.high_entropy_lines : [];
    if (highEntropyLines.length >= 1 && highEntropyLines.length <= 2) {
      anomalies.push({
        type: "isolated_high_entropy_line",
        details: {
          line_numbers: semanticHighEntropyLineNumbers(semanticPayload),
        },
      });
    }

    return {
      anomalies,
      anomaly_score: computeAnomalyScore(anomalies),
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
    const exitCode = Number.isFinite(Number(commandResult.exitCode)) ? Number(commandResult.exitCode) : null;
    const signal = typeof commandResult.signal === "string" ? commandResult.signal : null;
    const errorCode = commandFailed && typeof commandResult.error.code === "string" ? commandResult.error.code : "COMMAND_EXEC_FAILED";

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
          ...safeError(errorCode, commandResult.error.message || "Command execution failed"),
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

    let semanticAvailable = false;
    let semanticSummaryPreview;
    let anomalyScore = 0;
    let anomalyPreview = [];
    try {
      const semanticPayload = buildSemanticAnalysis(redactedStdout, redactedStderr);
      await writeSemanticFile(persisted.jobDir, semanticPayload);
      semanticAvailable = true;
      semanticSummaryPreview = {
        error_cluster_count: semanticPayload.error_clusters.length,
        stack_traces_detected: semanticPayload.stack_traces_detected,
        high_entropy_lines_count: semanticPayload.high_entropy_lines.length,
      };

      try {
        const anomalyPayload = extractAnomaliesFromSemantic(semanticPayload);
        await writeAnomalyFile(persisted.jobDir, anomalyPayload);
        anomalyScore = Number.isFinite(Number(anomalyPayload.anomaly_score)) ? Number(anomalyPayload.anomaly_score) : 0;
        anomalyPreview = Array.isArray(anomalyPayload.anomalies)
          ? anomalyPayload.anomalies.map((entry) => asString(entry?.type)).filter(Boolean)
          : [];
      } catch {
        anomalyScore = 0;
        anomalyPreview = [];
      }
    } catch {
      semanticAvailable = false;
      anomalyScore = 0;
      anomalyPreview = [];
    }

    const storedPayload = {
      ...basePayload,
      truncated: true,
      job_id: jobId,
      stdout_preview: redactedStdout.slice(0, 2000),
      stdout_tail: redactedStdout.slice(-2000),
      stderr_preview: redactedStderr.slice(0, 1000),
      retrieval_available: true,
      note: `Full output stored. Use ${SKILL_SLUG}_read_output_chunk or ${SKILL_SLUG}_search_output.`,
      semantic_available: semanticAvailable,
      ...(semanticAvailable ? { semantic_summary_preview: semanticSummaryPreview } : {}),
      anomaly_score: anomalyScore,
      anomaly_preview: anomalyPreview,
    };

    if (persisted.truncatedByStorageCap) {
      storedPayload.storage_capped = true;
    }

    if (commandFailed) {
      return {
        ...storedPayload,
        ...safeError(errorCode, commandResult.error.message || "Command execution failed"),
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

  function sortTagMap(tagsRaw) {
    const pairs = Object.entries(tagsRaw)
      .filter(([key, value]) => typeof key === "string" && key.trim() && typeof value === "string" && value.trim())
      .sort((left, right) => left[0].localeCompare(right[0]));
    return Object.fromEntries(pairs);
  }

  function normalizeBaselinesPayload(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw makeFailure("INVALID_BASELINES", "baselines.json must be an object");
    }

    const tags = payload.tags;
    if (!tags || typeof tags !== "object" || Array.isArray(tags)) {
      throw makeFailure("INVALID_BASELINES", "baselines.json.tags must be an object");
    }

    const normalized = {};
    for (const [key, value] of Object.entries(tags)) {
      const tag = validateBaselineTag(key);
      const jobId = validateJobId(value);
      normalized[tag] = jobId;
    }

    return {
      tags: sortTagMap(normalized),
    };
  }

  async function readBaselinesFile(options = {}) {
    const allowMissing = Boolean(options.allowMissing);
    const baselinePath = resolveToolBaselinesPath();

    try {
      await ensureReadableFile(baselinePath);
    } catch (error) {
      if (allowMissing && error && error.code === "NOT_FOUND") {
        return { tags: {} };
      }
      throw error;
    }

    let parsed;
    try {
      parsed = JSON.parse(await fsp.readFile(baselinePath, "utf8"));
    } catch (error) {
      throw makeFailure("INVALID_BASELINES", error.message || "baselines.json is not valid JSON");
    }

    return normalizeBaselinesPayload(parsed);
  }

  async function writeBaselinesFileAtomic(payload) {
    const normalized = normalizeBaselinesPayload(payload);
    const toolDir = resolveToolBaselinesDir();
    const baselinePath = resolveToolBaselinesPath();
    await fsp.mkdir(toolDir, { recursive: true });

    const tempName = `.baselines.json.tmp-${process.pid}-${Date.now()}-${randomHex(3)}`;
    const tempPath = path.join(toolDir, tempName);
    await fsp.writeFile(tempPath, JSON.stringify(normalized, null, 2), "utf8");
    await fsp.rename(tempPath, baselinePath);
  }

  async function ensureJobMetaExists(jobId) {
    const safeJobId = validateJobId(jobId);
    const jobDir = resolveJobDir(safeJobId);
    const metaPath = path.join(jobDir, "meta.json");
    await ensureReadableFile(metaPath);
    return safeJobId;
  }

  async function tagBaseline(args = {}) {
    const jobId = await ensureJobMetaExists(args.job_id);
    const tag = validateBaselineTag(args.tag);
    const baselines = await readBaselinesFile({ allowMissing: true });
    baselines.tags[tag] = jobId;
    const normalized = { tags: sortTagMap(baselines.tags) };
    await writeBaselinesFileAtomic(normalized);

    return {
      ok: true,
      job_id: jobId,
      tag,
    };
  }

  async function listBaselines() {
    const baselines = await readBaselinesFile({ allowMissing: true });
    return {
      ok: true,
      baselines: {
        tags: sortTagMap(baselines.tags),
      },
    };
  }

  async function diffAgainstBaseline(args = {}) {
    const jobId = await ensureJobMetaExists(args.job_id);
    const tag = validateBaselineTag(args.tag);
    const baselines = await readBaselinesFile({ allowMissing: false });
    const baseJobIdRaw = baselines.tags[tag];
    if (!baseJobIdRaw) {
      throw makeFailure("BASELINE_TAG_NOT_FOUND", `tag '${tag}' not found`);
    }
    const baseJobId = validateJobId(baseJobIdRaw);

    return readAnomalyDiff({
      base_job_id: baseJobId,
      compare_job_id: jobId,
    });
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

  async function readSemanticSummary(args = {}) {
    const jobId = validateJobId(args.job_id);
    const parsed = await readSemanticFile(jobId);

    return {
      ok: true,
      job_id: jobId,
      semantic: parsed,
    };
  }

  async function readSemanticFile(jobId) {
    const jobDir = resolveJobDir(jobId);
    const semanticPath = path.join(jobDir, "semantic.json");
    await ensureReadableFile(semanticPath);

    let parsed;
    try {
      parsed = JSON.parse(await fsp.readFile(semanticPath, "utf8"));
    } catch (error) {
      throw makeFailure("INVALID_SEMANTIC", error.message || "semantic.json is not valid JSON");
    }

    return parsed;
  }

  async function readAnomalyFile(jobId) {
    const jobDir = resolveJobDir(jobId);
    const anomalyPath = path.join(jobDir, "anomalies.json");
    await ensureReadableFile(anomalyPath);

    let parsed;
    try {
      parsed = JSON.parse(await fsp.readFile(anomalyPath, "utf8"));
    } catch (error) {
      throw makeFailure("INVALID_ANOMALY", error.message || "anomalies.json is not valid JSON");
    }

    return parsed;
  }

  async function readAnomalySummary(args = {}) {
    const jobId = validateJobId(args.job_id);
    const parsed = await readAnomalyFile(jobId);

    return {
      ok: true,
      job_id: jobId,
      anomalies: parsed,
    };
  }

  function normalizeAnomalyTypes(anomalyPayload) {
    const anomalies = Array.isArray(anomalyPayload?.anomalies) ? anomalyPayload.anomalies : [];
    const types = [];

    for (const anomaly of anomalies) {
      const type = asString(anomaly?.type).trim();
      if (type) {
        types.push(type);
      }
    }

    return Array.from(new Set(types)).sort((left, right) => left.localeCompare(right));
  }

  async function readAnomalyDiff(args = {}) {
    const baseJobId = validateJobId(args.base_job_id);
    const compareJobId = validateJobId(args.compare_job_id);

    if (baseJobId === compareJobId) {
      const anomalyPayload = await readAnomalyFile(baseJobId);
      return {
        ok: true,
        base_job_id: baseJobId,
        compare_job_id: compareJobId,
        score_delta: 0,
        severity_change: "unchanged",
        new_anomalies: [],
        resolved_anomalies: [],
        persistent_anomalies: normalizeAnomalyTypes(anomalyPayload),
      };
    }

    const [baseAnomaly, compareAnomaly] = await Promise.all([
      readAnomalyFile(baseJobId),
      readAnomalyFile(compareJobId),
    ]);

    const baseTypes = normalizeAnomalyTypes(baseAnomaly);
    const compareTypes = normalizeAnomalyTypes(compareAnomaly);
    const baseTypeSet = new Set(baseTypes);
    const compareTypeSet = new Set(compareTypes);

    const newAnomalies = compareTypes.filter((type) => !baseTypeSet.has(type));
    const resolvedAnomalies = baseTypes.filter((type) => !compareTypeSet.has(type));
    const persistentAnomalies = compareTypes.filter((type) => baseTypeSet.has(type));

    const baseScore = Number.isFinite(Number(baseAnomaly?.anomaly_score)) ? Number(baseAnomaly.anomaly_score) : 0;
    const compareScore = Number.isFinite(Number(compareAnomaly?.anomaly_score)) ? Number(compareAnomaly.anomaly_score) : 0;
    const scoreDelta = Number((compareScore - baseScore).toFixed(4));
    const severityChange = scoreDelta > 0 ? "increased" : (scoreDelta < 0 ? "decreased" : "unchanged");

    return {
      ok: true,
      base_job_id: baseJobId,
      compare_job_id: compareJobId,
      score_delta: scoreDelta,
      severity_change: severityChange,
      new_anomalies: newAnomalies,
      resolved_anomalies: resolvedAnomalies,
      persistent_anomalies: persistentAnomalies,
    };
  }

  function normalizeErrorClusters(semanticPayload) {
    const clusters = Array.isArray(semanticPayload?.error_clusters) ? semanticPayload.error_clusters : [];
    const out = new Map();

    for (const cluster of clusters) {
      if (!cluster || typeof cluster !== "object") {
        continue;
      }
      const signature = asString(cluster.signature || cluster.normalized_hash).trim();
      if (!signature) {
        continue;
      }
      const count = Number.isFinite(Number(cluster.count)) ? Number(cluster.count) : 0;
      out.set(signature, count);
    }

    return out;
  }

  function semanticArrayCount(semanticPayload, fieldName) {
    const value = semanticPayload?.[fieldName];
    return Array.isArray(value) ? value.length : 0;
  }

  function semanticNumber(semanticPayload, fieldName) {
    const value = semanticPayload?.[fieldName];
    return Number.isFinite(Number(value)) ? Number(value) : 0;
  }

  async function readSemanticDiff(args = {}) {
    const baseJobId = validateJobId(args.base_job_id);
    const compareJobId = validateJobId(args.compare_job_id);

    const [baseSemantic, compareSemantic] = await Promise.all([
      readSemanticFile(baseJobId),
      readSemanticFile(compareJobId),
    ]);

    const baseClusters = normalizeErrorClusters(baseSemantic);
    const compareClusters = normalizeErrorClusters(compareSemantic);
    const baseSignatures = Array.from(baseClusters.keys());
    const compareSignatures = Array.from(compareClusters.keys());

    const newErrorSignatures = compareSignatures
      .filter((signature) => !baseClusters.has(signature))
      .sort((left, right) => left.localeCompare(right));

    const removedErrorSignatures = baseSignatures
      .filter((signature) => !compareClusters.has(signature))
      .sort((left, right) => left.localeCompare(right));

    const changedErrorCounts = baseSignatures
      .filter((signature) => compareClusters.has(signature))
      .map((signature) => {
        const baseCount = baseClusters.get(signature) || 0;
        const compareCount = compareClusters.get(signature) || 0;
        return {
          signature,
          base_count: baseCount,
          compare_count: compareCount,
          delta: compareCount - baseCount,
        };
      })
      .filter((entry) => entry.delta !== 0)
      .sort((left, right) => left.signature.localeCompare(right.signature));

    const stackTraceDelta =
      semanticNumber(compareSemantic, "stack_traces_detected") -
      semanticNumber(baseSemantic, "stack_traces_detected");
    const highEntropyDelta =
      semanticArrayCount(compareSemantic, "high_entropy_lines") -
      semanticArrayCount(baseSemantic, "high_entropy_lines");

    return {
      ok: true,
      base_job_id: baseJobId,
      compare_job_id: compareJobId,
      new_error_signatures: newErrorSignatures,
      removed_error_signatures: removedErrorSignatures,
      changed_error_counts: changedErrorCounts,
      stack_trace_delta: stackTraceDelta,
      high_entropy_delta: highEntropyDelta,
    };
  }


  return {
    async run(args = {}) {
      try {
        const invocation = buildDockerInvocation(args);
        const commandResult = await executeCommand(invocation.command, invocation.commandArgs, 8 * 1024 * 1024);
        return await buildExecutionResponse(invocation.commandDisplay, commandResult);
      } catch (error) {
        return toSafeError(error, "RUN_FAILED", "Failed to execute tool");
      }
    },

    async health(args = {}) {
      try {
        const invocation = buildHealthInvocation();
        const commandResult = await executeCommand(invocation.command, invocation.commandArgs, 2 * 1024 * 1024);
        return await buildExecutionResponse(invocation.commandDisplay, commandResult);
      } catch (error) {
        return toSafeError(error, "HEALTH_FAILED", "Health check failed");
      }
    },

    async read_output_chunk(args = {}) {
      try {
        return await readOutputChunk(args);
      } catch (error) {
        return toSafeError(error, "READ_OUTPUT_CHUNK_FAILED", "Failed to read output chunk");
      }
    },

    async search_output(args = {}) {
      try {
        return await searchOutput(args);
      } catch (error) {
        return toSafeError(error, "SEARCH_OUTPUT_FAILED", "Failed to search output");
      }
    },

    async output_meta(args = {}) {
      try {
        return await readOutputMeta(args);
      } catch (error) {
        return toSafeError(error, "OUTPUT_META_FAILED", "Failed to read output metadata");
      }
    },

    async semantic_summary(args = {}) {
      try {
        return await readSemanticSummary(args);
      } catch (error) {
        return toSafeError(error, "SEMANTIC_SUMMARY_FAILED", "Failed to read semantic summary");
      }
    },

    async anomaly_summary(args = {}) {
      try {
        return await readAnomalySummary(args);
      } catch (error) {
        return toSafeError(error, "ANOMALY_SUMMARY_FAILED", "Failed to read anomaly summary");
      }
    },

    async tag_baseline(args = {}) {
      try {
        return await tagBaseline(args);
      } catch (error) {
        return toSafeError(error, "TAG_BASELINE_FAILED", "Failed to tag baseline");
      }
    },

    async list_baselines(args = {}) {
      try {
        return await listBaselines(args);
      } catch (error) {
        return toSafeError(error, "LIST_BASELINES_FAILED", "Failed to list baselines");
      }
    },

    async diff_against_baseline(args = {}) {
      try {
        return await diffAgainstBaseline(args);
      } catch (error) {
        return toSafeError(error, "DIFF_AGAINST_BASELINE_FAILED", "Failed to diff against baseline");
      }
    },

    async anomaly_diff(args = {}) {
      try {
        return await readAnomalyDiff(args);
      } catch (error) {
        return toSafeError(error, "ANOMALY_DIFF_FAILED", "Failed to diff anomaly summaries");
      }
    },

    async semantic_diff(args = {}) {
      try {
        return await readSemanticDiff(args);
      } catch (error) {
        return toSafeError(error, "SEMANTIC_DIFF_FAILED", "Failed to diff semantic summaries");
      }
    },
  };
}

module.exports = {
  createSkillRuntime,
};
