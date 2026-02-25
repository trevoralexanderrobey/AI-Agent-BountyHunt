const MAX_PARAMS_BYTES = 1024 * 1024;

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeSlug(rawSlug) {
  return typeof rawSlug === "string" ? rawSlug.trim().toLowerCase() : "";
}

function createToolValidator(registry) {
  async function validateExecutionRequest(rawSlug, params) {
    const errors = [];
    const slug = normalizeSlug(rawSlug);
    let adapter = null;

    if (!slug) {
      errors.push("Tool slug must be a non-empty string");
    } else {
      adapter = registry.get(slug);
      if (!adapter) {
        errors.push(`Tool '${slug}' is not registered or disabled`);
      }
    }

    if (!isPlainObject(params)) {
      errors.push("Tool params must be an object");
    }

    if (isPlainObject(params)) {
      let serialized = "";
      try {
        serialized = JSON.stringify(params);
      } catch {
        errors.push("Tool params must not be circular");
      }
      if (serialized && Buffer.byteLength(serialized, "utf8") >= MAX_PARAMS_BYTES) {
        errors.push("Tool params must be smaller than 1MB");
      }
    }

    if (adapter && errors.length === 0) {
      try {
        const validation = await adapter.validateInput(params);
        if (!validation || validation.valid !== true) {
          const adapterErrors = validation && Array.isArray(validation.errors) ? validation.errors : ["Tool input validation failed"];
          errors.push(...adapterErrors);
        }
      } catch (error) {
        errors.push(error && typeof error.message === "string" ? error.message : "Tool input validation failed");
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      adapter: errors.length === 0 ? adapter : undefined,
    };
  }

  return {
    validateExecutionRequest,
  };
}

module.exports = {
  createToolValidator,
};
