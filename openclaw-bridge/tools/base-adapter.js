const { resolveResourceLimits, validateResourceLimitsObject } = require("../execution/resource-policy.js");
const { DEFAULT_SANDBOX_POLICY } = require("../execution/sandbox-policy.js");
const { resolveToolImageReference } = require("../execution/tool-image-catalog.js");

class BaseToolAdapter {
  constructor(config = {}) {
    this.name = typeof config.name === "string" ? config.name : "";
    this.slug = typeof config.slug === "string" ? config.slug : "";
    this.description = typeof config.description === "string" ? config.description : "";
    this.executionMode = config && config.executionMode === "container" ? "container" : "host";
    this.containerRuntime = config && config.containerRuntime ? config.containerRuntime : null;
    this.containerRuntimeEnabled = Boolean(config && config.containerRuntimeEnabled === true);
    this.resourcePolicies =
      config && config.resourcePolicies && typeof config.resourcePolicies === "object" ? config.resourcePolicies : null;
    this.sandboxPolicies =
      config && config.sandboxPolicies && typeof config.sandboxPolicies === "object" ? config.sandboxPolicies : null;
    this.imagePolicies =
      config && config.imagePolicies && typeof config.imagePolicies === "object" ? config.imagePolicies : null;
    this.containerImages =
      config && config.containerImages && typeof config.containerImages === "object" ? config.containerImages : null;
    this.production = Boolean(config && config.production === true);
  }

  getResourceLimits() {
    return {
      timeoutMs: 30000,
      memoryMb: 512,
      maxOutputBytes: 10 * 1024 * 1024,
    };
  }

  /**
   * @param {{ params: Object, timeout: number, requestId: string, resourceLimits?: { cpuShares: number, memoryLimitMb: number, maxRuntimeSeconds: number, maxOutputBytes: number }, executionEligibility?: { allowed: boolean, reasonCode?: string, details?: Object } }} input
   * @returns {Promise<{ ok: boolean, result?: Object, error?: { code: string, message: string }, metadata: { executionTimeMs: number, outputBytes: number, requestId: string } }>}
   */
  async execute(input) {
    const startedAt = Date.now();
    const requestId = input && typeof input.requestId === "string" ? input.requestId : "";
    let outputBytes = 0;

    try {
      const params = this.ensureObject(input ? input.params : undefined, "Input params must be an object");
      const validation = await this.validateInput(params);
      if (!validation || validation.valid !== true) {
        const messages = validation && Array.isArray(validation.errors) ? validation.errors : ["Invalid tool input"];
        throw this.makeError("INVALID_TOOL_INPUT", messages.join("; "));
      }

      const limits = this.getResourceLimits();
      const timeoutMs = this.resolveTimeout(input ? input.timeout : undefined, limits.timeoutMs);

      const rawResult =
        this.executionMode === "container"
          ? await this.executeInContainer({ params, timeout: timeoutMs, requestId, input })
          : await this.withTimeout(this.executeImpl({ params, timeout: timeoutMs, requestId }), timeoutMs);
      const normalized = await this.normalizeOutput(rawResult);
      const payload = this.ensureObject(normalized, "Normalized output must be an object");

      outputBytes = this.computeOutputBytes(payload);
      if (outputBytes > limits.maxOutputBytes) {
        throw this.makeError("TOOL_OUTPUT_TOO_LARGE", "Tool output exceeded maxOutputBytes");
      }

      return {
        ok: true,
        result: payload,
        metadata: {
          executionTimeMs: Date.now() - startedAt,
          outputBytes,
          requestId,
        },
      };
    } catch (error) {
      const wrapped = this.wrapError(error);
      return {
        ok: false,
        error: wrapped,
        metadata: {
          executionTimeMs: Date.now() - startedAt,
          outputBytes,
          requestId,
        },
      };
    }
  }

  async executeImpl(_input) {
    throw this.makeError("NOT_IMPLEMENTED", "executeImpl() must be implemented by subclass");
  }

  async executeContainerImpl(input) {
    return this.buildContainerInvocation({
      params: input.params,
      timeout: input.timeout,
      requestId: input.requestId,
      inputArtifacts: await this.buildContainerInputArtifacts({
        params: input.params,
        timeout: input.timeout,
        requestId: input.requestId,
      }),
    });
  }

  async validateInput(_params) {
    throw this.makeError("NOT_IMPLEMENTED", "validateInput() must be implemented by subclass");
  }

  async normalizeOutput(_rawOutput) {
    throw this.makeError("NOT_IMPLEMENTED", "normalizeOutput() must be implemented by subclass");
  }

  ensureObject(value, message) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
    throw this.makeError("INVALID_TOOL_INPUT", message || "Expected object");
  }

  resolveTimeout(inputTimeout, fallbackTimeout) {
    const value = Number(inputTimeout);
    if (!Number.isFinite(value) || value <= 0) {
      return fallbackTimeout;
    }
    return Math.floor(value);
  }

  withTimeout(promise, timeoutMs) {
    return new Promise((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => {
        if (done) {
          return;
        }
        done = true;
        reject(this.makeError("TOOL_EXECUTION_ERROR", "Tool execution timed out"));
      }, timeoutMs);

      Promise.resolve(promise)
        .then((value) => {
          if (done) {
            return;
          }
          done = true;
          clearTimeout(timer);
          resolve(value);
        })
        .catch((error) => {
          if (done) {
            return;
          }
          done = true;
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  parseJson(rawOutput) {
    if (typeof rawOutput === "string") {
      try {
        return JSON.parse(rawOutput);
      } catch {
        return { output: rawOutput };
      }
    }
    return rawOutput;
  }

  computeOutputBytes(payload) {
    try {
      return Buffer.byteLength(JSON.stringify(payload), "utf8");
    } catch {
      return 0;
    }
  }

  makeError(code, message) {
    const error = new Error(String(message || "Tool execution failed"));
    error.code = String(code || "TOOL_EXECUTION_ERROR");
    return error;
  }

  wrapError(error) {
    const code = error && typeof error.code === "string" ? error.code : "TOOL_EXECUTION_ERROR";
    const message = error && typeof error.message === "string" ? error.message : "Tool execution failed";
    return { code, message };
  }

  resolveExecutionEligibility(input) {
    if (!input || typeof input !== "object") {
      return {
        allowed: true,
        reasonCode: "",
        details: {},
      };
    }

    const eligibility = input.executionEligibility;
    if (!eligibility || typeof eligibility !== "object") {
      return {
        allowed: true,
        reasonCode: "",
        details: {},
      };
    }

    return {
      allowed: eligibility.allowed !== false,
      reasonCode: typeof eligibility.reasonCode === "string" ? eligibility.reasonCode : "",
      details: eligibility.details && typeof eligibility.details === "object" ? eligibility.details : {},
    };
  }

  ensureExecutionEligibility(input) {
    const eligibility = this.resolveExecutionEligibility(input);
    if (eligibility.allowed) {
      return;
    }

    const reasonCode = eligibility.reasonCode || "EXECUTION_SUPPRESSED_BY_CLUSTER_STATE";
    throw this.makeError(
      "EXECUTION_SUPPRESSED_BY_CLUSTER_STATE",
      `Container execution is suppressed by cluster state (${reasonCode})`,
    );
  }

  resolveContainerImage() {
    const imageRef = resolveToolImageReference(this.slug, {
      images: this.containerImages || undefined,
    });

    if (!imageRef) {
      throw this.makeError("INVALID_CONTAINER_REQUEST", `Container image is not defined for tool '${this.slug || ""}'`);
    }

    return imageRef;
  }

  resolveSandboxConfig() {
    const sandboxConfig =
      this.sandboxPolicies && this.slug && this.sandboxPolicies[this.slug] && typeof this.sandboxPolicies[this.slug] === "object"
        ? this.sandboxPolicies[this.slug]
        : DEFAULT_SANDBOX_POLICY;

    return {
      runAsNonRoot: sandboxConfig.runAsNonRoot,
      dropCapabilities: Array.isArray(sandboxConfig.dropCapabilities) ? sandboxConfig.dropCapabilities.slice() : [],
      privileged: sandboxConfig.privileged,
      hostPID: sandboxConfig.hostPID,
      hostNetwork: sandboxConfig.hostNetwork,
      hostMounts: sandboxConfig.hostMounts,
      readOnlyRootFilesystem: sandboxConfig.readOnlyRootFilesystem,
      writableVolumes: Array.isArray(sandboxConfig.writableVolumes) ? sandboxConfig.writableVolumes.slice() : [],
      seccompProfile: sandboxConfig.seccompProfile,
      appArmorProfile: sandboxConfig.appArmorProfile,
    };
  }

  resolveSignatureVerified() {
    if (this.imagePolicies && this.slug && this.imagePolicies[this.slug] && typeof this.imagePolicies[this.slug] === "object") {
      const perTool = this.imagePolicies[this.slug];
      if (Object.prototype.hasOwnProperty.call(perTool, "signatureVerified")) {
        return perTool.signatureVerified === true;
      }
    }

    return false;
  }

  async buildContainerInputArtifacts({ params, timeout, requestId }) {
    const payload = {
      slug: this.slug,
      params,
      timeout,
      requestId,
    };

    return [
      {
        kind: "inlineText",
        contents: JSON.stringify(payload),
        targetPath: "/scratch/request.json",
      },
    ];
  }

  buildContainerInvocation({ params, timeout, requestId, inputArtifacts }) {
    return {
      image: this.resolveContainerImage(),
      args: [],
      env: {
        OPENCLAW_REQUEST_PATH: "/scratch/request.json",
        OPENCLAW_TOOL_SLUG: this.slug,
      },
      inputArtifacts: Array.isArray(inputArtifacts) ? inputArtifacts : [],
      sandboxConfig: this.resolveSandboxConfig(),
      signatureVerified: this.resolveSignatureVerified(),
      requestId,
    };
  }

  async executeInContainer({ params, timeout, requestId, input }) {
    if (!this.containerRuntimeEnabled) {
      throw this.makeError(
        "CONTAINER_RUNTIME_DISABLED",
        "Container runtime is disabled; set execution.containerRuntimeEnabled=true to enable container execution",
      );
    }

    this.ensureExecutionEligibility(input);

    if (!this.containerRuntime || typeof this.containerRuntime.runContainer !== "function") {
      throw this.makeError("CONTAINER_RUNTIME_REQUIRED", "Container runtime required for container execution mode");
    }

    const requestedLimitsResult = this.normalizeRequestedResourceLimits(input ? input.resourceLimits : undefined);
    if (!requestedLimitsResult.valid) {
      const message = requestedLimitsResult.errors.length
        ? requestedLimitsResult.errors.join("; ")
        : "Explicit resourceLimits are required for container execution mode";
      throw this.makeError("RESOURCE_LIMITS_REQUIRED", message);
    }
    const requestedLimits = requestedLimitsResult.limits;

    let policyLimits;
    try {
      policyLimits = resolveResourceLimits(this.slug, {
        allowDefault: false,
        policies: this.resourcePolicies || undefined,
      });
    } catch (error) {
      if (error && typeof error.code === "string") {
        throw error;
      }
      throw this.makeError(
        "RESOURCE_POLICY_UNDEFINED",
        `Resource policy is required for container mode tool '${this.slug || ""}'`,
      );
    }

    this.ensureRequestedWithinPolicy(requestedLimits, policyLimits);

    const invocation = await this.executeContainerImpl({
      params,
      timeout,
      requestId,
      resourceLimits: requestedLimits,
    });
    const request = this.ensureObject(invocation, "Container invocation must be an object");
    if (typeof request.image !== "string" || request.image.trim().length === 0) {
      throw this.makeError("INVALID_CONTAINER_REQUEST", "Container invocation must include image");
    }

    return this.withTimeout(
      this.containerRuntime.runContainer({
        ...request,
        resourceLimits: requestedLimits,
        toolSlug: this.slug,
        requestId,
      }),
      timeout,
    );
  }

  normalizeRequestedResourceLimits(resourceLimits) {
    if (!resourceLimits || typeof resourceLimits !== "object") {
      return {
        valid: false,
        limits: null,
        errors: ["Explicit resourceLimits are required for container execution mode"],
      };
    }

    const validation = validateResourceLimitsObject(resourceLimits, {
      rejectUnknown: true,
      label: "input.resourceLimits",
    });
    return {
      valid: validation.valid,
      limits: validation.valid ? validation.limits : null,
      errors: validation.valid ? [] : validation.errors,
    };
  }

  ensureRequestedWithinPolicy(requested, policy) {
    const keys = ["cpuShares", "memoryLimitMb", "maxRuntimeSeconds", "maxOutputBytes"];
    for (const key of keys) {
      const requestedValue = requested[key];
      const policyValue = policy && policy[key];

      if (
        typeof requestedValue !== "number" ||
        !Number.isFinite(requestedValue) ||
        !Number.isInteger(requestedValue) ||
        requestedValue <= 0 ||
        typeof policyValue !== "number" ||
        !Number.isFinite(policyValue) ||
        !Number.isInteger(policyValue) ||
        policyValue <= 0
      ) {
        throw this.makeError("RESOURCE_POLICY_INVALID", `Missing or invalid resource limit '${key}'`);
      }

      if (requestedValue > policyValue) {
        throw this.makeError(
          "RESOURCE_LIMIT_EXCEEDED",
          `Requested ${key} (${requestedValue}) exceeds policy limit (${policyValue})`,
        );
      }
    }
  }
}

module.exports = {
  BaseToolAdapter,
};
