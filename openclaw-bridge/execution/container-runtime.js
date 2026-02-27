const crypto = require("node:crypto");

const { validateImageReference } = require("./image-policy.js");
const { validateSandboxConfig } = require("./sandbox-policy.js");
const { validateResourceLimitsObject } = require("./resource-policy.js");
const { createContainerAudit } = require("./container-audit.js");

const SUPPORTED_BACKENDS = Object.freeze(["mock", "docker", "containerd"]);
const RUN_CONTAINER_KEYS = Object.freeze([
  "image",
  "args",
  "env",
  "resourceLimits",
  "toolSlug",
  "sandboxConfig",
  "signatureVerified",
]);

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
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

function validateRunContainerInputShape(input) {
  if (!isPlainObject(input)) {
    throw makeFailure("INVALID_CONTAINER_REQUEST", "runContainer input must be an object");
  }

  for (const key of Object.keys(input)) {
    if (!RUN_CONTAINER_KEYS.includes(key)) {
      throw makeFailure("INVALID_CONTAINER_REQUEST", `runContainer input contains unknown field '${key}'`);
    }
  }

  for (const key of RUN_CONTAINER_KEYS) {
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
}

function createMockBackend() {
  const containers = new Map();

  return {
    async runContainer(input) {
      const now = Date.now();
      const containerId = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
      const entry = {
        containerId,
        image: input.image,
        args: input.args.slice(),
        env: { ...input.env },
        resourceLimits: { ...input.resourceLimits },
        createdAt: now,
        state: "MOCK_RUNNING",
      };
      containers.set(containerId, entry);

      return {
        ok: true,
        backend: "mock",
        containerId,
        state: entry.state,
        image: entry.image,
      };
    },

    async stopContainer(containerId) {
      const key = typeof containerId === "string" ? containerId.trim() : "";
      if (!key || !containers.has(key)) {
        throw makeFailure("CONTAINER_NOT_FOUND", "Container was not found", { containerId: key });
      }
      const existing = containers.get(key);
      existing.state = "MOCK_STOPPED";
      existing.stoppedAt = Date.now();
      return {
        ok: true,
        backend: "mock",
        containerId: key,
        state: existing.state,
      };
    },

    async inspectContainer(containerId) {
      const key = typeof containerId === "string" ? containerId.trim() : "";
      if (!key || !containers.has(key)) {
        throw makeFailure("CONTAINER_NOT_FOUND", "Container was not found", { containerId: key });
      }
      const existing = containers.get(key);
      return {
        ok: true,
        backend: "mock",
        containerId: key,
        state: existing.state,
        image: existing.image,
        createdAt: existing.createdAt,
        stoppedAt: existing.stoppedAt || null,
        resourceLimits: { ...existing.resourceLimits },
      };
    },
  };
}

function createDisabledBackend(name) {
  return {
    async runContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only in Phase 19A`);
    },
    async stopContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only in Phase 19A`);
    },
    async inspectContainer() {
      throw makeFailure("CONTAINER_BACKEND_DISABLED", `Backend '${name}' is scaffolding-only in Phase 19A`);
    },
  };
}

function createContainerRuntime(options = {}) {
  const backendName = resolveBackendName(options);
  const production = Boolean(options.production);
  const audit = createContainerAudit({
    logger: options.auditLogger,
    metrics: options.metrics,
  });

  const backends = {
    mock: createMockBackend(),
    docker: createDisabledBackend("docker"),
    containerd: createDisabledBackend("containerd"),
  };
  const backend = backends[backendName];

  async function runContainer(input = {}) {
    validateRunContainerInputShape(input);

    const resourceValidation = validateResourceLimitsObject(input.resourceLimits, {
      rejectUnknown: true,
      label: "resourceLimits",
    });
    if (!resourceValidation.valid) {
      throw makeFailure("RESOURCE_LIMITS_REQUIRED", resourceValidation.errors.join("; "), {
        errors: resourceValidation.errors,
      });
    }

    const sandboxValidation = validateSandboxConfig(input.sandboxConfig);
    if (!sandboxValidation.valid) {
      throw makeFailure("SANDBOX_POLICY_VIOLATION", sandboxValidation.errors.join("; "), {
        errors: sandboxValidation.errors,
      });
    }

    if (sandboxValidation.policy.runAsNonRoot !== true) {
      throw makeFailure("SANDBOX_POLICY_VIOLATION", "Container execution requires non-root sandbox policy");
    }

    const imageValidation = validateImageReference(input.image, {
      production,
      allowedRegistries: options.allowedRegistries,
      requireDigestPinning: true,
      requireSignatureVerification: true,
      signatureVerified: input.signatureVerified,
    });
    if (!imageValidation.valid) {
      throw makeFailure("IMAGE_POLICY_VIOLATION", imageValidation.errors.join("; "), {
        errors: imageValidation.errors,
      });
    }

    const startedAt = Date.now();
    const result = await backend.runContainer({
      image: input.image.trim(),
      args: input.args.slice(),
      env: { ...input.env },
      resourceLimits: resourceValidation.limits,
      toolSlug: input.toolSlug.trim(),
      sandboxConfig: sandboxValidation.policy,
      signatureVerified: input.signatureVerified,
    });

    audit.recordStart({
      containerId: result.containerId,
      image: input.image,
      startTime: startedAt,
      resourceUsage: {
        cpuShares: resourceValidation.limits.cpuShares,
        memoryLimitMb: resourceValidation.limits.memoryLimitMb,
      },
      args: input.args,
      env: input.env,
    });

    return result;
  }

  async function stopContainer(containerId) {
    const stopTime = Date.now();
    const inspected = await backend.inspectContainer(containerId);
    const result = await backend.stopContainer(containerId);

    audit.recordStop({
      containerId,
      image: inspected && inspected.image ? inspected.image : "",
      stopTime,
      exitCode: 0,
      resourceUsage: inspected && inspected.resourceLimits ? inspected.resourceLimits : {},
    });

    return result;
  }

  async function inspectContainer(containerId) {
    return backend.inspectContainer(containerId);
  }

  return {
    runContainer,
    stopContainer,
    inspectContainer,
    backend: backendName,
  };
}

module.exports = {
  SUPPORTED_BACKENDS,
  RUN_CONTAINER_KEYS,
  createContainerRuntime,
};
