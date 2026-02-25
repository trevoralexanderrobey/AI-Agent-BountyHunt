const { createPersistentStore, CONTROL_PLANE_STATE_VERSION } = require("./persistent-store.js");

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function createStateManager(options = {}) {
  const version = parsePositiveInt(options.version, CONTROL_PLANE_STATE_VERSION);
  const buildState = typeof options.buildState === "function" ? options.buildState : () => ({});
  const applyState = typeof options.applyState === "function" ? options.applyState : async () => {};
  const onError = typeof options.onError === "function" ? options.onError : () => {};
  const store =
    options.store && typeof options.store.load === "function" && typeof options.store.scheduleWrite === "function"
      ? options.store
      : createPersistentStore({
          path: options.path,
          debounceMs: options.debounceMs,
        });

  let initialized = false;
  let lastLoadInfo = null;

  function emitError(code, message) {
    try {
      onError({
        code,
        message,
      });
    } catch {}
  }

  async function initialize() {
    const loaded = await store.load();
    lastLoadInfo = loaded;
    initialized = true;

    if (!loaded.ok) {
      emitError(loaded.code || "STATE_LOAD_FAILED", loaded.message || "Failed to load state");
      return {
        ok: true,
        loaded: false,
        reason: loaded.code || "STATE_LOAD_FAILED",
      };
    }

    if (!loaded.state || !isPlainObject(loaded.state)) {
      return {
        ok: true,
        loaded: false,
        reason: loaded.exists ? "EMPTY_STATE" : "STATE_FILE_MISSING",
      };
    }

    const fileVersion = Number(loaded.state.version);
    if (!Number.isFinite(fileVersion) || fileVersion !== version) {
      return {
        ok: true,
        loaded: false,
        reason: "VERSION_MISMATCH",
      };
    }

    const payload = isPlainObject(loaded.state.payload) ? loaded.state.payload : {};
    try {
      await applyState(payload);
    } catch (error) {
      emitError("STATE_APPLY_FAILED", error && typeof error.message === "string" ? error.message : "Failed to apply state");
      return {
        ok: true,
        loaded: false,
        reason: "STATE_APPLY_FAILED",
      };
    }

    return {
      ok: true,
      loaded: true,
      version: fileVersion,
    };
  }

  function schedulePersist(reason = "update") {
    if (!initialized) {
      return;
    }

    let payload = {};
    try {
      const built = buildState();
      payload = isPlainObject(built) ? built : {};
    } catch (error) {
      emitError("STATE_BUILD_FAILED", error && typeof error.message === "string" ? error.message : "Failed to build state");
      return;
    }

    store.scheduleWrite({
      version,
      persistedAt: Date.now(),
      reason: typeof reason === "string" ? reason : "update",
      payload,
    });
  }

  async function flush() {
    if (!initialized) {
      return {
        ok: true,
        wrote: false,
      };
    }
    return store.flush();
  }

  async function shutdown() {
    if (!initialized) {
      return {
        ok: true,
        wrote: false,
      };
    }
    return store.close();
  }

  return {
    getPath: () => (typeof store.getPath === "function" ? store.getPath() : ""),
    initialize,
    schedulePersist,
    flush,
    shutdown,
    getLastLoadInfo: () => lastLoadInfo,
  };
}

module.exports = {
  createStateManager,
};
