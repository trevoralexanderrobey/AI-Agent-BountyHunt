class BaseToolAdapter {
  constructor(config = {}) {
    this.name = typeof config.name === "string" ? config.name : "";
    this.slug = typeof config.slug === "string" ? config.slug : "";
    this.description = typeof config.description === "string" ? config.description : "";
  }

  getResourceLimits() {
    return {
      timeoutMs: 30000,
      memoryMb: 512,
      maxOutputBytes: 10 * 1024 * 1024,
    };
  }

  /**
   * @param {{ params: Object, timeout: number, requestId: string }} input
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

      const rawResult = await this.withTimeout(this.executeImpl({ params, timeout: timeoutMs, requestId }), timeoutMs);
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
}

module.exports = {
  BaseToolAdapter,
};
