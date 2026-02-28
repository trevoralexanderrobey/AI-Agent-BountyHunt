const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { Writable } = require("node:stream");

const Docker = require("dockerode");
const tar = require("tar-stream");

const { validateImageReference } = require("./image-policy.js");
const { validateSandboxConfig } = require("./sandbox-policy.js");
const { resolveResourceLimits, validateResourceLimitsObject } = require("./resource-policy.js");
const { validateEgressPolicy } = require("./egress-policy.js");
const { createContainerAudit } = require("./container-audit.js");

const SUPPORTED_BACKENDS = Object.freeze(["mock", "docker", "containerd"]);
const RUN_CONTAINER_REQUIRED_KEYS = Object.freeze([
  "image",
  "args",
  "env",
  "resourceLimits",
  "toolSlug",
  "sandboxConfig",
  "signatureVerified",
]);
const RUN_CONTAINER_OPTIONAL_KEYS = Object.freeze(["inputArtifacts", "requestId", "principalHash"]);
const RUN_CONTAINER_KEYS = Object.freeze([...RUN_CONTAINER_REQUIRED_KEYS, ...RUN_CONTAINER_OPTIONAL_KEYS]);

const CONTAINER_LABEL_ENABLED = "com.openclaw.execution";
const CONTAINER_LABEL_TOOL = "com.openclaw.tool";
const CONTAINER_LABEL_REQUEST = "com.openclaw.request_id";
const CONTAINER_LABEL_RUNTIME = "com.openclaw.runtime_id";
const CONTAINER_LABEL_VOLUME = "com.openclaw.volume";
const CONTAINER_LABEL_PRINCIPAL_HASH = "com.openclaw.principal_hash";
const CONTAINER_LABEL_CPU_SHARES = "com.openclaw.resource.cpu_shares";
const CONTAINER_LABEL_MEMORY_MB = "com.openclaw.resource.memory_mb";
const CONTAINER_LABEL_RUNTIME_SECONDS = "com.openclaw.resource.max_runtime_seconds";
const CONTAINER_LABEL_OUTPUT_BYTES = "com.openclaw.resource.max_output_bytes";

const DEFAULT_EXTERNAL_NETWORK = "openclaw-execution-net";
const DEFAULT_INTERNAL_NETWORK = "openclaw-execution-internal";

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  return fallback;
}

function parsePositiveInteger(value, fallback = null) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function makeFailure(code, message, details) {
  const error = new Error(String(message || "Container runtime error"));
  error.code = String(code || "CONTAINER_RUNTIME_ERROR");
  if (typeof details !== "undefined") {
    error.details = details;
  }
  return error;
}

function normalizeBackendName(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function resolveBackendName(options) {
  const explicitBackend = normalizeBackendName(options.backend);
  if (explicitBackend) {
    if (!SUPPORTED_BACKENDS.includes(explicitBackend)) {
      throw makeFailure("CONTAINER_BACKEND_INVALID", `Unsupported container backend '${explicitBackend}'`, {
        backend: explicitBackend,
        source: "options.backend",
      });
    }
    return explicitBackend;
  }

  const nestedBackend = normalizeBackendName(options && options.execution && options.execution.backend);
  if (nestedBackend) {
    if (!SUPPORTED_BACKENDS.includes(nestedBackend)) {
      throw makeFailure("CONTAINER_BACKEND_INVALID", `Unsupported container backend '${nestedBackend}'`, {
        backend: nestedBackend,
        source: "options.execution.backend",
      });
    }
    return nestedBackend;
  }

  const envBackend = normalizeBackendName(process.env.CONTAINER_RUNTIME_BACKEND);
  if (envBackend) {
    if (!SUPPORTED_BACKENDS.includes(envBackend)) {
      throw makeFailure("CONTAINER_BACKEND_INVALID", `Unsupported container backend '${envBackend}'`, {
        backend: envBackend,
        source: "CONTAINER_RUNTIME_BACKEND",
      });
    }
    return envBackend;
  }

  return "mock";
}

function resolveRuntimeEnabled(options) {
  if (Object.prototype.hasOwnProperty.call(options || {}, "containerRuntimeEnabled")) {
    return Boolean(options.containerRuntimeEnabled);
  }

  if (options && options.execution && Object.prototype.hasOwnProperty.call(options.execution, "containerRuntimeEnabled")) {
    return Boolean(options.execution.containerRuntimeEnabled);
  }

  if (typeof process.env.CONTAINER_RUNTIME_ENABLED !== "undefined") {
    return parseBoolean(process.env.CONTAINER_RUNTIME_ENABLED, false);
  }

  return false;
}

function resolveProduction(options) {
  if (Object.prototype.hasOwnProperty.call(options || {}, "production")) {
    return Boolean(options.production);
  }

  const env = normalizeString(process.env.NODE_ENV).toLowerCase();
  return env === "production";
}

function resolveExecutionConfig(options) {
  const execution = options && options.execution && isPlainObject(options.execution) ? options.execution : {};
  return {
    resourcePolicies: isPlainObject(options.resourcePolicies) ? options.resourcePolicies : execution.resourcePolicies,
    egressPolicies: isPlainObject(options.egressPolicies) ? options.egressPolicies : execution.egressPolicies,
    allowedRegistries: Array.isArray(options.allowedRegistries)
      ? options.allowedRegistries
      : Array.isArray(execution.allowedImageRegistries)
      ? execution.allowedImageRegistries
      : undefined,
    externalNetworkName: normalizeString(options.externalNetworkName || execution.externalNetworkName) || DEFAULT_EXTERNAL_NETWORK,
    internalNetworkName: normalizeString(options.internalNetworkName || execution.internalNetworkName) || DEFAULT_INTERNAL_NETWORK,
    nonRootUser: normalizeString(options.nonRootUser || execution.nonRootUser) || "openclaw",
    requireSignatureVerificationInProduction: Object.prototype.hasOwnProperty.call(
      options,
      "requireSignatureVerificationInProduction",
    )
      ? Boolean(options.requireSignatureVerificationInProduction)
      : Object.prototype.hasOwnProperty.call(execution, "requireSignatureVerificationInProduction")
      ? Boolean(execution.requireSignatureVerificationInProduction)
      : true,
    requireSignatureVerification: Object.prototype.hasOwnProperty.call(options, "requireSignatureVerification")
      ? Boolean(options.requireSignatureVerification)
      : Object.prototype.hasOwnProperty.call(execution, "requireSignatureVerification")
      ? Boolean(execution.requireSignatureVerification)
      : false,
    egressAnomalyThresholdPerMinute: parsePositiveInteger(
      options.egressAnomalyThresholdPerMinute,
      parsePositiveInteger(execution.egressAnomalyThresholdPerMinute, 100),
    ),
  };
}

function validateRunContainerInputShape(input) {
  if (!isPlainObject(input)) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "runContainer input must be an object");
  }

  for (const key of Object.keys(input)) {
    if (!RUN_CONTAINER_KEYS.includes(key)) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", `runContainer input contains unknown field '${key}'`);
    }
  }

  for (const key of RUN_CONTAINER_REQUIRED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", `runContainer input is missing required field '${key}'`);
    }
  }

  if (typeof input.image !== "string" || input.image.trim().length === 0) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "image must be a non-empty string");
  }

  if (typeof input.toolSlug !== "string" || input.toolSlug.trim().length === 0) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "toolSlug must be a non-empty string");
  }

  if (!Array.isArray(input.args) || input.args.some((item) => typeof item !== "string")) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "args must be an array of strings");
  }

  if (!isPlainObject(input.env)) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "env must be an object");
  }

  if (!isPlainObject(input.sandboxConfig)) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "sandboxConfig must be an object");
  }

  if (typeof input.signatureVerified !== "boolean") {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "signatureVerified must be a boolean");
  }

  if (Object.prototype.hasOwnProperty.call(input, "requestId")) {
    const requestId = normalizeString(input.requestId);
    if (!requestId) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", "requestId must be a non-empty string when provided");
    }
  }

  if (Object.prototype.hasOwnProperty.call(input, "principalHash")) {
    const principalHash = normalizeString(input.principalHash).toLowerCase();
    if (principalHash && !/^[a-f0-9]{8,64}$/.test(principalHash)) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", "principalHash must be a lowercase hex string when provided");
    }
  }

  if (Object.prototype.hasOwnProperty.call(input, "inputArtifacts")) {
    validateInputArtifacts(input.inputArtifacts);
  }
}

function normalizeContainerPath(rawPath) {
  const source = normalizeString(rawPath);
  const normalized = path.posix.normalize(source);
  if (!normalized.startsWith("/scratch/")) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "artifact targetPath must be within /scratch/");
  }
  if (normalized.includes("..")) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "artifact targetPath must not include traversal");
  }
  return normalized;
}

function validateInputArtifacts(inputArtifacts) {
  if (!Array.isArray(inputArtifacts)) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "inputArtifacts must be an array when provided");
  }

  for (const artifact of inputArtifacts) {
    if (!isPlainObject(artifact)) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", "inputArtifacts entries must be objects");
    }

    const kind = normalizeString(artifact.kind).toLowerCase();
    if (kind !== "hostpath" && kind !== "inlinetext") {
      throw makeFailure("INVALID_CONTAINER_REQUEST", "inputArtifacts.kind must be hostPath or inlineText");
    }

    normalizeContainerPath(artifact.targetPath);

    if (kind === "hostpath") {
      const sourcePath = normalizeString(artifact.sourcePath);
      if (!sourcePath) {
        throw makeFailure("INVALID_CONTAINER_REQUEST", "hostPath artifact requires sourcePath");
      }
    } else if (typeof artifact.contents !== "string") {
      throw makeFailure("INVALID_CONTAINER_REQUEST", "inlineText artifact requires contents string");
    }
  }
}

function normalizeResourceLimits(rawLimits) {
  const source = isPlainObject(rawLimits) ? rawLimits : {};
  return {
    cpuShares: parsePositiveInteger(source.cpuShares, null),
    memoryLimitMb: parsePositiveInteger(source.memoryLimitMb, null),
    maxRuntimeSeconds: parsePositiveInteger(source.maxRuntimeSeconds, null),
    maxOutputBytes: parsePositiveInteger(source.maxOutputBytes, null),
  };
}

function buildDockerEnv(env, input) {
  const entries = [];
  for (const [key, value] of Object.entries(env || {})) {
    if (typeof key !== "string" || key.trim().length === 0) {
      continue;
    }
    entries.push(`${key}=${String(value ?? "")}`);
  }

  const requestId = normalizeString(input.requestId);
  if (requestId) {
    entries.push(`OPENCLAW_REQUEST_ID=${requestId}`);
  }

  entries.push("TMPDIR=/scratch/tmp");
  return entries;
}

function createCaptureStream(maxBytes) {
  let bytes = 0;
  let overflowed = false;
  const chunks = [];

  const stream = new Writable({
    write(chunk, _encoding, callback) {
      if (overflowed) {
        callback();
        return;
      }

      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      bytes += buffer.length;
      if (bytes > maxBytes) {
        overflowed = true;
      } else {
        chunks.push(buffer);
      }
      callback();
    },
  });

  return {
    stream,
    getResult() {
      return {
        text: Buffer.concat(chunks).toString("utf8"),
        overflowed,
        bytes,
      };
    },
  };
}

function parseRunnerPayload(stdoutText) {
  const source = String(stdoutText || "").trim();
  if (!source) {
    throw makeFailure("TOOL_EXECUTION_ERROR", "Container returned empty output");
  }

  try {
    return JSON.parse(source);
  } catch {
    const lines = source.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length === 0) {
      throw makeFailure("TOOL_EXECUTION_ERROR", "Container returned invalid JSON output");
    }
    try {
      return JSON.parse(lines[lines.length - 1]);
    } catch {
      throw makeFailure("TOOL_EXECUTION_ERROR", "Container returned invalid JSON output");
    }
  }
}

function createNoopMetrics() {
  return {
    increment: () => {},
    observe: () => {},
    gauge: () => {},
  };
}

function createNoopLogger() {
  return {
    info: () => {},
    error: () => {},
  };
}

function createSafeLogger(rawLogger) {
  const noop = createNoopLogger();
  const source = rawLogger && typeof rawLogger === "object" ? rawLogger : noop;
  return {
    info: (...args) => {
      try {
        if (typeof source.info === "function") {
          source.info(...args);
        } else if (typeof source.log === "function") {
          source.log(...args);
        }
      } catch {}
    },
    error: (...args) => {
      try {
        if (typeof source.error === "function") {
          source.error(...args);
        } else if (typeof source.log === "function") {
          source.log(...args);
        }
      } catch {}
    },
  };
}

function createSafeMetrics(rawMetrics) {
  const noop = createNoopMetrics();
  const source = rawMetrics && typeof rawMetrics === "object" ? rawMetrics : noop;
  return {
    increment: (...args) => {
      try {
        if (typeof source.increment === "function") {
          source.increment(...args);
        }
      } catch {}
    },
    observe: (...args) => {
      try {
        if (typeof source.observe === "function") {
          source.observe(...args);
        }
      } catch {}
    },
    gauge: (...args) => {
      try {
        if (typeof source.gauge === "function") {
          source.gauge(...args);
        }
      } catch {}
    },
  };
}

function createRuntimeCircuit(config = {}) {
  const stateByTool = new Map();
  const threshold = Number.isFinite(Number(config.threshold)) ? Math.max(1, Math.floor(Number(config.threshold))) : 5;
  const windowMs = Number.isFinite(Number(config.windowMs)) ? Math.max(1000, Math.floor(Number(config.windowMs))) : 60000;
  const openMs = Number.isFinite(Number(config.openMs)) ? Math.max(1000, Math.floor(Number(config.openMs))) : 30000;

  function getState(toolSlug) {
    const slug = normalizeString(toolSlug).toLowerCase();
    if (!slug) {
      return null;
    }

    let state = stateByTool.get(slug);
    if (!state) {
      state = {
        failures: [],
        openUntil: 0,
      };
      stateByTool.set(slug, state);
    }
    return state;
  }

  function recordFailure(toolSlug, now = Date.now()) {
    const state = getState(toolSlug);
    if (!state) {
      return;
    }

    state.failures = state.failures.filter((timestamp) => now - timestamp <= windowMs);
    state.failures.push(now);
    if (state.failures.length >= threshold) {
      state.openUntil = now + openMs;
      state.failures = [];
    }
  }

  function recordSuccess(toolSlug) {
    const state = getState(toolSlug);
    if (!state) {
      return;
    }
    state.failures = [];
    state.openUntil = 0;
  }

  function assertClosed(toolSlug, now = Date.now()) {
    const state = getState(toolSlug);
    if (!state) {
      return;
    }
    if (state.openUntil > now) {
      throw makeFailure("CONTAINER_RUNTIME_CIRCUIT_OPEN", "Container runtime circuit is open for tool", {
        toolSlug,
        openUntil: state.openUntil,
      });
    }
  }

  return {
    recordFailure,
    recordSuccess,
    assertClosed,
  };
}

async function createArchiveBuffer(files) {
  return new Promise((resolve, reject) => {
    const pack = tar.pack();
    const chunks = [];

    pack.on("data", (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    pack.on("error", (error) => reject(error));
    pack.on("end", () => resolve(Buffer.concat(chunks)));

    const directories = new Set();
    for (const file of files) {
      const normalizedTarget = normalizeContainerPath(file.targetPath);
      const relative = normalizedTarget.replace(/^\//, "");
      const dir = path.posix.dirname(relative);
      if (dir && dir !== ".") {
        const parts = dir.split("/");
        let current = "";
        for (const part of parts) {
          current = current ? `${current}/${part}` : part;
          directories.add(current);
        }
      }
    }

    const sortedDirectories = Array.from(directories).sort((a, b) => a.length - b.length);

    (async () => {
      for (const dir of sortedDirectories) {
        await new Promise((resolveEntry, rejectEntry) => {
          pack.entry({ name: `${dir}/`, type: "directory", mode: 0o755 }, (error) => {
            if (error) {
              rejectEntry(error);
              return;
            }
            resolveEntry();
          });
        });
      }

      for (const file of files) {
        const normalizedTarget = normalizeContainerPath(file.targetPath);
        const relative = normalizedTarget.replace(/^\//, "");
        const data = Buffer.isBuffer(file.contents) ? file.contents : Buffer.from(String(file.contents), "utf8");
        await new Promise((resolveEntry, rejectEntry) => {
          pack.entry({ name: relative, mode: 0o600 }, data, (error) => {
            if (error) {
              rejectEntry(error);
              return;
            }
            resolveEntry();
          });
        });
      }

      pack.finalize();
    })().catch((error) => {
      reject(error);
    });
  });
}

async function resolveArtifactContents(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length === 0) {
    return [];
  }

  const files = [];
  for (const rawArtifact of artifacts) {
    const artifact = rawArtifact || {};
    const normalizedKind = normalizeString(artifact.kind).toLowerCase();
    const targetPath = normalizeContainerPath(artifact.targetPath);

    if (normalizedKind === "hostpath") {
      const sourcePath = normalizeString(artifact.sourcePath);
      if (!sourcePath) {
        throw makeFailure("INVALID_CONTAINER_REQUEST", "hostPath artifact requires sourcePath");
      }
      const fileData = await fs.readFile(sourcePath);
      files.push({
        targetPath,
        contents: fileData,
      });
      continue;
    }

    if (normalizedKind === "inlinetext") {
      files.push({
        targetPath,
        contents: String(artifact.contents || ""),
      });
      continue;
    }

    throw makeFailure("INVALID_CONTAINER_REQUEST", "Unsupported input artifact kind");
  }

  return files;
}

function parseContainerStats(stats) {
  if (!stats || typeof stats !== "object") {
    return {
      memoryUsageBytes: 0,
      cpuUsageNano: 0,
    };
  }

  const memoryUsageBytes = Number.isFinite(Number(stats.memory_stats && stats.memory_stats.usage))
    ? Number(stats.memory_stats.usage)
    : 0;
  const cpuUsageNano = Number.isFinite(Number(stats.cpu_stats && stats.cpu_stats.cpu_usage && stats.cpu_stats.cpu_usage.total_usage))
    ? Number(stats.cpu_stats.cpu_usage.total_usage)
    : 0;

  return {
    memoryUsageBytes,
    cpuUsageNano,
  };
}

function createMockBackend() {
  const containers = new Map();

  return {
    async runContainer(input) {
      const containerId = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
      containers.set(containerId, {
        containerId,
        image: input.image,
        createdAt: Date.now(),
        state: "MOCK_RUNNING",
        requestId: normalizeString(input.requestId),
        principalHash: normalizeString(input.principalHash).toLowerCase(),
        toolSlug: normalizeString(input.toolSlug).toLowerCase(),
        resourceLimits: normalizeResourceLimits(input.resourceLimits),
      });

      return {
        backend: "mock",
        containerId,
        rawResult: {
          backend: "mock",
          toolSlug: input.toolSlug,
          mocked: true,
        },
        exitCode: 0,
        stats: {
          memoryUsageBytes: 0,
          cpuUsageNano: 0,
        },
      };
    },

    async stopContainer(containerId) {
      const key = normalizeString(containerId);
      if (!key || !containers.has(key)) {
        throw makeFailure("CONTAINER_NOT_FOUND", "Container was not found", { containerId: key });
      }
      const record = containers.get(key);
      record.state = "MOCK_STOPPED";
      record.stoppedAt = Date.now();
      return {
        ok: true,
        backend: "mock",
        containerId: key,
      };
    },

    async inspectContainer(containerId) {
      const key = normalizeString(containerId);
      if (!key || !containers.has(key)) {
        throw makeFailure("CONTAINER_NOT_FOUND", "Container was not found", { containerId: key });
      }

      const record = containers.get(key);
      return {
        ok: true,
        backend: "mock",
        containerId: key,
        image: record.image,
        state: record.state,
        createdAt: record.createdAt,
        stoppedAt: record.stoppedAt || null,
      };
    },

    async listActiveExecutions() {
      return Array.from(containers.values())
        .filter((record) => record.state === "MOCK_RUNNING")
        .map((record) => ({
          containerId: record.containerId,
          requestId: record.requestId,
          principalHash: record.principalHash,
          toolSlug: record.toolSlug,
          resourceLimits: normalizeResourceLimits(record.resourceLimits),
          createdAt: record.createdAt,
        }));
    },

    async sweepOrphans() {
      return { removedContainers: 0, removedVolumes: 0 };
    },
  };
}

function createDisabledBackend(name) {
  return {
    async runContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only`);
    },
    async stopContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only`);
    },
    async inspectContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only`);
    },
    async listActiveExecutions() {
      return [];
    },
    async sweepOrphans() {
      return { removedContainers: 0, removedVolumes: 0 };
    },
  };
}

async function createDockerBackend({ docker, executionConfig, metrics, runtimeId, activeExecutions }) {
  try {
    await docker.ping();
  } catch (error) {
    throw makeFailure("CONTAINER_BACKEND_INIT_FAILED", "Docker backend initialization failed", {
      reason: error && error.message ? error.message : String(error),
    });
  }

  async function ensureNetwork(name, options = {}) {
    const normalizedName = normalizeString(name);
    if (!normalizedName) {
      throw makeFailure("CONTAINER_RUNTIME_ERROR", "Docker network name is required");
    }

    const found = await docker.listNetworks({
      filters: {
        name: [normalizedName],
      },
    });
    if (Array.isArray(found) && found.length > 0) {
      return normalizedName;
    }

    await docker.createNetwork({
      Name: normalizedName,
      Driver: "bridge",
      Internal: options.internal === true,
      Labels: {
        [CONTAINER_LABEL_ENABLED]: "true",
        [CONTAINER_LABEL_RUNTIME]: runtimeId,
      },
    });
    return normalizedName;
  }

  async function removeContainerSafe(containerId) {
    if (!containerId) {
      return;
    }

    try {
      const container = docker.getContainer(containerId);
      await container.remove({ force: true, v: false });
    } catch {}
  }

  async function removeVolumeSafe(volumeName) {
    if (!volumeName) {
      return;
    }
    try {
      const volume = docker.getVolume(volumeName);
      await volume.remove();
    } catch {}
  }

  async function collectStatsSafe(container) {
    try {
      const stats = await container.stats({ stream: false });
      return parseContainerStats(stats);
    } catch {
      return {
        memoryUsageBytes: 0,
        cpuUsageNano: 0,
      };
    }
  }

  async function runContainer(input, context = {}) {
    const timeoutMs = Number.isFinite(Number(context.timeoutMs)) ? Math.max(1000, Number(context.timeoutMs)) : 30000;
    const maxOutputBytes = Number.isFinite(Number(context.maxOutputBytes)) ? Math.max(1024, Number(context.maxOutputBytes)) : 5 * 1024 * 1024;

    const allowExternalNetwork = Boolean(context.egressPolicy && context.egressPolicy.policy && context.egressPolicy.policy.allowedExternalNetwork);
    const networkName = await ensureNetwork(
      allowExternalNetwork ? executionConfig.externalNetworkName : executionConfig.internalNetworkName,
      { internal: allowExternalNetwork ? false : true },
    );

    const volumeName = `openclaw-scratch-${runtimeId}-${crypto.randomBytes(6).toString("hex")}`;
    await docker.createVolume({
      Name: volumeName,
      Labels: {
        [CONTAINER_LABEL_ENABLED]: "true",
        [CONTAINER_LABEL_RUNTIME]: runtimeId,
      },
    });

    const requestId = normalizeString(input.requestId);
    const principalHash = normalizeString(input.principalHash).toLowerCase();
    const labels = {
      [CONTAINER_LABEL_ENABLED]: "true",
      [CONTAINER_LABEL_TOOL]: input.toolSlug,
      [CONTAINER_LABEL_RUNTIME]: runtimeId,
      [CONTAINER_LABEL_VOLUME]: volumeName,
      [CONTAINER_LABEL_CPU_SHARES]: String(input.resourceLimits.cpuShares),
      [CONTAINER_LABEL_MEMORY_MB]: String(input.resourceLimits.memoryLimitMb),
      [CONTAINER_LABEL_RUNTIME_SECONDS]: String(input.resourceLimits.maxRuntimeSeconds),
      [CONTAINER_LABEL_OUTPUT_BYTES]: String(input.resourceLimits.maxOutputBytes),
    };
    if (requestId) {
      labels[CONTAINER_LABEL_REQUEST] = requestId;
    }
    if (principalHash) {
      labels[CONTAINER_LABEL_PRINCIPAL_HASH] = principalHash;
    }

    const securityOpt = [];
    if (typeof input.sandboxConfig.seccompProfile === "string" && input.sandboxConfig.seccompProfile.trim()) {
      securityOpt.push(`seccomp=${input.sandboxConfig.seccompProfile.trim()}`);
    }
    if (typeof input.sandboxConfig.appArmorProfile === "string" && input.sandboxConfig.appArmorProfile.trim()) {
      securityOpt.push(`apparmor=${input.sandboxConfig.appArmorProfile.trim()}`);
    }

    const memoryBytes = input.resourceLimits.memoryLimitMb * 1024 * 1024;
    const hostConfig = {
      AutoRemove: false,
      Memory: memoryBytes,
      CpuShares: input.resourceLimits.cpuShares,
      ReadonlyRootfs: true,
      Privileged: false,
      PidMode: "private",
      NetworkMode: networkName,
      CapDrop: ["ALL"],
      Binds: [`${volumeName}:/scratch:rw`],
      PortBindings: {},
    };

    if (securityOpt.length > 0) {
      hostConfig.SecurityOpt = securityOpt;
    }

    const container = await docker.createContainer({
      Image: input.image,
      Cmd: input.args,
      Env: buildDockerEnv(input.env, input),
      WorkingDir: "/scratch",
      User: executionConfig.nonRootUser,
      AttachStdout: true,
      AttachStderr: true,
      Labels: labels,
      HostConfig: hostConfig,
    });

    const containerId = container.id;
    activeExecutions.set(containerId, {
      containerId,
      volumeName,
      toolSlug: input.toolSlug,
      createdAt: Date.now(),
    });

    let exitCode = -1;
    let timedOut = false;

    try {
      const files = await resolveArtifactContents(input.inputArtifacts || []);
      if (files.length > 0) {
        const tarBuffer = await createArchiveBuffer(files);
        await container.putArchive(tarBuffer, {
          path: "/",
        });
      }

      const attachedStream = await container.attach({
        stream: true,
        stdout: true,
        stderr: true,
        logs: true,
      });

      const stdoutCapture = createCaptureStream(maxOutputBytes);
      const stderrCapture = createCaptureStream(maxOutputBytes);

      docker.modem.demuxStream(attachedStream, stdoutCapture.stream, stderrCapture.stream);

      const logsDone = new Promise((resolve) => {
        attachedStream.once("end", resolve);
        attachedStream.once("close", resolve);
      });

      await container.start();

      const waitPromise = container.wait();
      let waitResult;
      const timeoutPromise = new Promise((_, reject) => {
        const timer = setTimeout(() => {
          timedOut = true;
          reject(makeFailure("TOOL_EXECUTION_ERROR", "Container execution timed out"));
        }, timeoutMs);
        if (typeof timer.unref === "function") {
          timer.unref();
        }
        waitPromise.finally(() => {
          clearTimeout(timer);
        });
      });

      try {
        waitResult = await Promise.race([waitPromise, timeoutPromise]);
      } catch (error) {
        if (timedOut) {
          try {
            await container.kill();
          } catch {}
        }
        throw error;
      }

      exitCode = Number.isFinite(Number(waitResult && waitResult.StatusCode)) ? Number(waitResult.StatusCode) : -1;
      await Promise.race([logsDone, new Promise((resolve) => setTimeout(resolve, 500))]);

      const stdoutResult = stdoutCapture.getResult();
      const stderrResult = stderrCapture.getResult();
      if (stdoutResult.overflowed || stderrResult.overflowed) {
        throw makeFailure("TOOL_OUTPUT_TOO_LARGE", "Container output exceeded maxOutputBytes");
      }

      const payload = parseRunnerPayload(stdoutResult.text);
      if (!payload || payload.ok !== true) {
        const errorPayload = payload && payload.error && typeof payload.error === "object" ? payload.error : {};
        const code = typeof errorPayload.code === "string" ? errorPayload.code : "TOOL_EXECUTION_ERROR";
        const message =
          typeof errorPayload.message === "string"
            ? errorPayload.message
            : normalizeString(stderrResult.text) || "Container tool execution failed";
        throw makeFailure(code, message, {
          stderr: normalizeString(stderrResult.text),
        });
      }

      const stats = await collectStatsSafe(container);
      return {
        backend: "docker",
        containerId,
        rawResult: payload.rawResult,
        exitCode,
        stats,
      };
    } finally {
      activeExecutions.delete(containerId);

      try {
        await removeContainerSafe(containerId);
      } catch (error) {
        metrics.increment("tool.container.cleanup.error", {
          code: "CONTAINER_CLEANUP_FAILED",
          phase: "container",
          tool: input.toolSlug,
        });
      }

      try {
        await removeVolumeSafe(volumeName);
      } catch {
        metrics.increment("tool.container.cleanup.error", {
          code: "CONTAINER_CLEANUP_FAILED",
          phase: "volume",
          tool: input.toolSlug,
        });
      }
    }
  }

  async function stopContainer(containerId) {
    const key = normalizeString(containerId);
    if (!key) {
      throw makeFailure("CONTAINER_NOT_FOUND", "Container id is required");
    }

    const container = docker.getContainer(key);
    try {
      await container.stop({ t: 5 });
    } catch {}

    try {
      await container.remove({ force: true });
    } catch {}

    return {
      ok: true,
      backend: "docker",
      containerId: key,
    };
  }

  async function inspectContainer(containerId) {
    const key = normalizeString(containerId);
    if (!key) {
      throw makeFailure("CONTAINER_NOT_FOUND", "Container id is required");
    }

    const container = docker.getContainer(key);
    const info = await container.inspect();
    return {
      ok: true,
      backend: "docker",
      containerId: key,
      state: info && info.State ? info.State.Status : "",
      image: info && info.Config ? info.Config.Image : "",
      createdAt: info && info.Created ? Date.parse(info.Created) || null : null,
      exitCode: info && info.State && Number.isFinite(Number(info.State.ExitCode)) ? Number(info.State.ExitCode) : null,
    };
  }

  async function listActiveExecutions() {
    const running = await docker.listContainers({
      all: false,
      filters: {
        label: [`${CONTAINER_LABEL_ENABLED}=true`],
      },
    });

    return (Array.isArray(running) ? running : []).map((container) => {
      const labels = container && isPlainObject(container.Labels) ? container.Labels : {};
      const requestId = normalizeString(labels[CONTAINER_LABEL_REQUEST]);
      const toolSlug = normalizeString(labels[CONTAINER_LABEL_TOOL]).toLowerCase();
      const principalHash = normalizeString(labels[CONTAINER_LABEL_PRINCIPAL_HASH]).toLowerCase();
      const createdAt = Number.isFinite(Number(container.Created)) ? Number(container.Created) * 1000 : Date.now();
      const resourceLimits = {
        cpuShares: parsePositiveInteger(labels[CONTAINER_LABEL_CPU_SHARES], null),
        memoryLimitMb: parsePositiveInteger(labels[CONTAINER_LABEL_MEMORY_MB], null),
        maxRuntimeSeconds: parsePositiveInteger(labels[CONTAINER_LABEL_RUNTIME_SECONDS], null),
        maxOutputBytes: parsePositiveInteger(labels[CONTAINER_LABEL_OUTPUT_BYTES], null),
      };

      return {
        containerId: normalizeString(container && container.Id),
        requestId,
        principalHash,
        toolSlug,
        resourceLimits,
        createdAt,
      };
    });
  }

  async function sweepOrphans() {
    const removedContainers = [];
    const removedVolumes = [];

    const containers = await docker.listContainers({
      all: true,
      filters: {
        label: [`${CONTAINER_LABEL_ENABLED}=true`],
      },
    });

    for (const item of containers) {
      const containerId = normalizeString(item && item.Id);
      if (!containerId || activeExecutions.has(containerId)) {
        continue;
      }

      const state = normalizeString(item && item.State).toLowerCase();
      const status = normalizeString(item && item.Status).toLowerCase();
      const removable = state !== "running" || status.includes("exited") || status.includes("created");
      if (!removable) {
        continue;
      }

      try {
        const container = docker.getContainer(containerId);
        await container.remove({ force: true, v: false });
        removedContainers.push(containerId);
      } catch {}
    }

    const volumesInfo = await docker.listVolumes({
      filters: {
        label: [`${CONTAINER_LABEL_ENABLED}=true`],
      },
    });

    const volumes = volumesInfo && Array.isArray(volumesInfo.Volumes) ? volumesInfo.Volumes : [];
    for (const volume of volumes) {
      const name = normalizeString(volume && volume.Name);
      if (!name) {
        continue;
      }

      try {
        const ref = docker.getVolume(name);
        await ref.remove();
        removedVolumes.push(name);
      } catch {}
    }

    return {
      removedContainers: removedContainers.length,
      removedVolumes: removedVolumes.length,
    };
  }

  return {
    runContainer,
    stopContainer,
    inspectContainer,
    listActiveExecutions,
    sweepOrphans,
  };
}

function createContainerRuntime(options = {}) {
  const backendName = resolveBackendName(options);
  const production = resolveProduction(options);
  const runtimeEnabled = resolveRuntimeEnabled(options);
  const executionConfig = resolveExecutionConfig(options);
  const metrics = createSafeMetrics(options.metrics);
  const logger = createSafeLogger(options.logger || options.auditLogger);
  const audit = createContainerAudit({
    logger: options.auditLogger,
    metrics,
  });
  const circuit = createRuntimeCircuit(options.runtimeCircuit);
  const runtimeId = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
  const activeExecutions = new Map();

  let backend = null;
  if (backendName === "mock") {
    backend = createMockBackend();
  } else if (backendName === "containerd") {
    backend = createDisabledBackend("containerd");
  } else if (backendName === "docker") {
    const docker = new Docker(options.dockerOptions || {});
    backend = {
      __promise: createDockerBackend({
        docker,
        executionConfig,
        metrics,
        runtimeId,
        activeExecutions,
      }),
      __docker: docker,
    };
  }

  let backendPromise = null;
  if (backend && backend.__promise) {
    backendPromise = backend.__promise;
  }

  let orphanTimer = null;
  const egressEventsByBucket = new Map();

  function recordEgressEvent(toolSlug, egressValidation) {
    const normalizedTool = normalizeString(toolSlug).toLowerCase() || "unknown";
    const allowedExternal = Boolean(
      egressValidation &&
        egressValidation.policy &&
        isPlainObject(egressValidation.policy) &&
        egressValidation.policy.allowedExternalNetwork === true,
    );

    if (!allowedExternal) {
      return;
    }

    const minuteBucket = Math.floor(Date.now() / 60000);
    const key = `${normalizedTool}:${minuteBucket}`;
    const nextCount = (egressEventsByBucket.get(key) || 0) + 1;
    egressEventsByBucket.set(key, nextCount);

    metrics.increment("tool.container.egress.external_event", {
      tool: normalizedTool,
      minute_bucket: String(minuteBucket),
    });

    const threshold = parsePositiveInteger(executionConfig.egressAnomalyThresholdPerMinute, 100);
    if (nextCount > threshold) {
      metrics.increment("tool.container.egress.anomaly", {
        tool: normalizedTool,
        minute_bucket: String(minuteBucket),
      });
      logger.error({
        event: "tool_container_egress_anomaly",
        tool: normalizedTool,
        minute_bucket: minuteBucket,
        count: nextCount,
        threshold,
        timestamp: new Date().toISOString(),
      });
    }

    const cutoffBucket = minuteBucket - 2;
    for (const mapKey of egressEventsByBucket.keys()) {
      const suffix = mapKey.split(":").pop() || "";
      const parsedBucket = Number.parseInt(suffix, 10);
      if (Number.isFinite(parsedBucket) && parsedBucket < cutoffBucket) {
        egressEventsByBucket.delete(mapKey);
      }
    }
  }

  async function resolveBackend() {
    if (backendPromise) {
      const resolved = await backendPromise;
      backendPromise = null;
      backend = resolved;
      return resolved;
    }
    return backend;
  }

  function ensureRuntimeEnabled() {
    if (!runtimeEnabled) {
      throw makeFailure(
        "CONTAINER_RUNTIME_DISABLED",
        "Container runtime is disabled; set execution.containerRuntimeEnabled=true to enable",
      );
    }
  }

  async function runContainer(input = {}) {
    ensureRuntimeEnabled();
    validateRunContainerInputShape(input);

    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    try {
      circuit.assertClosed(toolSlug);
    } catch (error) {
      metrics.increment("circuit.open", { tool: toolSlug });
      throw error;
    }

    const resourceValidation = validateResourceLimitsObject(input.resourceLimits, {
      rejectUnknown: true,
      label: "resourceLimits",
    });
    if (!resourceValidation.valid) {
      throw makeFailure("RESOURCE_LIMITS_REQUIRED", resourceValidation.errors.join("; "), {
        errors: resourceValidation.errors,
      });
    }

    const policyLimits = resolveResourceLimits(toolSlug, {
      policies: executionConfig.resourcePolicies,
      allowDefault: false,
    });

    for (const key of ["cpuShares", "memoryLimitMb", "maxRuntimeSeconds", "maxOutputBytes"]) {
      const requested = resourceValidation.limits[key];
      const policy = policyLimits[key];
      if (!Number.isFinite(Number(requested)) || Number(requested) <= 0) {
        throw makeFailure("RESOURCE_LIMITS_REQUIRED", `resourceLimits.${key} must be a positive integer`);
      }
      if (!Number.isFinite(Number(policy)) || Number(policy) <= 0 || Number(requested) > Number(policy)) {
        throw makeFailure("RESOURCE_LIMIT_EXCEEDED", `resourceLimits.${key} exceeds policy limit`, {
          requested,
          policy,
          key,
        });
      }
    }

    const sandboxValidation = validateSandboxConfig(input.sandboxConfig);
    if (!sandboxValidation.valid) {
      throw makeFailure("SANDBOX_POLICY_VIOLATION", sandboxValidation.errors.join("; "), {
        errors: sandboxValidation.errors,
      });
    }

    const egressValidation = validateEgressPolicy(toolSlug, executionConfig.egressPolicies, {
      allowDefault: !production,
    });
    if (!egressValidation.valid) {
      throw makeFailure("EGRESS_POLICY_UNDEFINED", egressValidation.errors.join("; "), {
        errors: egressValidation.errors,
      });
    }
    recordEgressEvent(toolSlug, egressValidation);

    const requireSignatureVerification = production
      ? executionConfig.requireSignatureVerificationInProduction
      : executionConfig.requireSignatureVerification;
    const imageValidation = validateImageReference(input.image, {
      production,
      allowedRegistries: executionConfig.allowedRegistries,
      requireDigestPinning: true,
      requireSignatureVerification,
      signatureVerified: input.signatureVerified,
    });
    if (!imageValidation.valid) {
      throw makeFailure("IMAGE_POLICY_VIOLATION", imageValidation.errors.join("; "), {
        errors: imageValidation.errors,
      });
    }

    const runtimeUser = normalizeString(executionConfig.nonRootUser).toLowerCase();
    if (!runtimeUser || runtimeUser === "root" || runtimeUser === "0") {
      throw makeFailure("SANDBOX_POLICY_VIOLATION", "Container runtime requires a non-root execution user");
    }

    const startedAt = Date.now();
    const resolvedBackend = await resolveBackend();

    audit.recordStart({
      containerId: "pending",
      image: input.image,
      startTime: startedAt,
      resourceUsage: {
        cpuShares: resourceValidation.limits.cpuShares,
        memoryLimitMb: resourceValidation.limits.memoryLimitMb,
      },
      args: input.args,
      env: input.env,
    });

    try {
      const result = await resolvedBackend.runContainer(
        {
          ...input,
          image: input.image.trim(),
          toolSlug,
          resourceLimits: resourceValidation.limits,
          sandboxConfig: sandboxValidation.policy,
          inputArtifacts: input.inputArtifacts || [],
        },
        {
          timeoutMs: resourceValidation.limits.maxRuntimeSeconds * 1000,
          maxOutputBytes: resourceValidation.limits.maxOutputBytes,
          egressPolicy: egressValidation,
        },
      );

      const stopTime = Date.now();
      const stats = result && result.stats ? result.stats : { memoryUsageBytes: 0, cpuUsageNano: 0 };
      metrics.observe("tool.container.duration", Math.max(0, stopTime - startedAt), { tool: toolSlug });
      metrics.observe("tool.container.memory_usage", Math.max(0, Number(stats.memoryUsageBytes) || 0), { tool: toolSlug });
      metrics.observe("tool.container.cpu_usage", Math.max(0, Number(stats.cpuUsageNano) || 0), { tool: toolSlug });
      metrics.gauge("tool.container.exit_code", Number.isFinite(Number(result.exitCode)) ? Number(result.exitCode) : 0, {
        tool: toolSlug,
      });

      audit.recordStop({
        containerId: result.containerId,
        image: input.image,
        startTime: startedAt,
        stopTime,
        exitCode: Number.isFinite(Number(result.exitCode)) ? Number(result.exitCode) : 0,
        resourceUsage: {
          cpuShares: resourceValidation.limits.cpuShares,
          memoryLimitMb: resourceValidation.limits.memoryLimitMb,
          memoryUsageBytes: stats.memoryUsageBytes || 0,
          cpuUsageNano: stats.cpuUsageNano || 0,
        },
      });

      circuit.recordSuccess(toolSlug);

      return result.rawResult;
    } catch (error) {
      const stopTime = Date.now();
      circuit.recordFailure(toolSlug, stopTime);

      if (error && error.code === "TOOL_EXECUTION_ERROR" && /timed out/i.test(String(error.message || ""))) {
        audit.recordTimeout({
          containerId: "unknown",
          image: input.image,
          startTime: startedAt,
          stopTime,
          exitCode: 124,
        });
      } else {
        audit.recordCrash({
          containerId: "unknown",
          image: input.image,
          startTime: startedAt,
          stopTime,
          exitCode: -1,
        });
      }

      throw error;
    }
  }

  async function stopContainer(containerId) {
    const resolvedBackend = await resolveBackend();
    return resolvedBackend.stopContainer(containerId);
  }

  async function inspectContainer(containerId) {
    const resolvedBackend = await resolveBackend();
    return resolvedBackend.inspectContainer(containerId);
  }

  async function listActiveExecutions() {
    const resolvedBackend = await resolveBackend();
    if (!resolvedBackend || typeof resolvedBackend.listActiveExecutions !== "function") {
      return [];
    }
    const records = await resolvedBackend.listActiveExecutions();
    return Array.isArray(records) ? records : [];
  }

  async function sweepOrphans() {
    const resolvedBackend = await resolveBackend();
    if (!resolvedBackend || typeof resolvedBackend.sweepOrphans !== "function") {
      return {
        removedContainers: 0,
        removedVolumes: 0,
      };
    }

    const result = await resolvedBackend.sweepOrphans();
    const removedContainers = Number.isFinite(Number(result && result.removedContainers))
      ? Math.max(0, Number(result.removedContainers))
      : 0;
    const removedVolumes = Number.isFinite(Number(result && result.removedVolumes))
      ? Math.max(0, Number(result.removedVolumes))
      : 0;

    if (removedContainers > 0) {
      metrics.increment("container.orphan.cleaned", {
        resource: "container",
        removed: String(removedContainers),
      });
    }
    if (removedVolumes > 0) {
      metrics.increment("container.orphan.cleaned", {
        resource: "volume",
        removed: String(removedVolumes),
      });
    }
    if (removedContainers > 0 || removedVolumes > 0) {
      metrics.increment("orphan.cleanup", {
        removed_containers: String(removedContainers),
        removed_volumes: String(removedVolumes),
      });
    }

    return {
      removedContainers,
      removedVolumes,
    };
  }

  function startOrphanSweeper(intervalMs = 60000) {
    if (orphanTimer) {
      return;
    }

    const ms = Number.isFinite(Number(intervalMs)) ? Math.max(5000, Math.floor(Number(intervalMs))) : 60000;
    orphanTimer = setInterval(() => {
      sweepOrphans()
        .then((result) => {
          metrics.increment("tool.container.orphan_sweep", {
            removedContainers: result && result.removedContainers ? result.removedContainers : 0,
            removedVolumes: result && result.removedVolumes ? result.removedVolumes : 0,
          });
        })
        .catch(() => {});
    }, ms);

    if (orphanTimer && typeof orphanTimer.unref === "function") {
      orphanTimer.unref();
    }
  }

  function stopOrphanSweeper() {
    if (!orphanTimer) {
      return;
    }
    clearInterval(orphanTimer);
    orphanTimer = null;
  }

  if (backendName === "docker" && runtimeEnabled) {
    startOrphanSweeper(options.orphanSweepIntervalMs);
  }

  return {
    runContainer,
    stopContainer,
    inspectContainer,
    listActiveExecutions,
    sweepOrphans,
    startOrphanSweeper,
    stopOrphanSweeper,
    backend: backendName,
    containerRuntimeEnabled: runtimeEnabled,
  };
}

module.exports = {
  SUPPORTED_BACKENDS,
  RUN_CONTAINER_KEYS,
  RUN_CONTAINER_REQUIRED_KEYS,
  RUN_CONTAINER_OPTIONAL_KEYS,
  createContainerRuntime,
};
