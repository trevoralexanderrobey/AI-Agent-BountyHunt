const fs = require("node:fs/promises");
const path = require("node:path");

const CONTROL_PLANE_STATE_VERSION = 1;
const DEFAULT_STORE_PATH = "./data/control-plane-state.json";
const DEFAULT_DEBOUNCE_MS = 1000;

function normalizeDebounceMs(value) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_DEBOUNCE_MS;
  }
  return parsed;
}

function resolveStorePath(rawPath) {
  const fromEnv = typeof process.env.STATE_STORE_PATH === "string" ? process.env.STATE_STORE_PATH.trim() : "";
  const candidate = typeof rawPath === "string" && rawPath.trim() ? rawPath.trim() : fromEnv || DEFAULT_STORE_PATH;
  return path.resolve(candidate);
}

function createPersistentStore(options = {}) {
  const storePath = resolveStorePath(options.path);
  const debounceMs = normalizeDebounceMs(options.debounceMs);

  let pendingEnvelope = null;
  let writeTimer = null;
  let writeChain = Promise.resolve();
  let closed = false;

  async function writeAtomic(envelope) {
    const directory = path.dirname(storePath);
    await fs.mkdir(directory, { recursive: true });

    const tempPath = `${storePath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const body = `${JSON.stringify(envelope, null, 2)}\n`;
    await fs.writeFile(tempPath, body, { encoding: "utf8" });
    await fs.rename(tempPath, storePath);
  }

  function runExclusive(task) {
    const next = writeChain.then(task, task);
    writeChain = next.catch(() => {});
    return next;
  }

  async function load() {
    let raw = "";
    try {
      raw = await fs.readFile(storePath, "utf8");
    } catch (error) {
      if (error && error.code === "ENOENT") {
        return {
          ok: true,
          state: null,
          exists: false,
          path: storePath,
        };
      }
      return {
        ok: false,
        code: "STATE_FILE_READ_FAILED",
        message: error && typeof error.message === "string" ? error.message : "Failed to read state file",
        state: null,
        path: storePath,
      };
    }

    const trimmed = raw.trim();
    if (!trimmed) {
      return {
        ok: true,
        state: null,
        exists: true,
        path: storePath,
      };
    }

    try {
      const parsed = JSON.parse(trimmed);
      return {
        ok: true,
        state: parsed,
        exists: true,
        path: storePath,
      };
    } catch (error) {
      return {
        ok: false,
        code: "STATE_FILE_CORRUPTED",
        message: error && typeof error.message === "string" ? error.message : "State file is corrupted",
        state: null,
        path: storePath,
      };
    }
  }

  function scheduleWrite(envelope) {
    if (closed) {
      return;
    }
    pendingEnvelope = envelope;
    if (writeTimer) {
      return;
    }
    writeTimer = setTimeout(() => {
      writeTimer = null;
      void flush();
    }, debounceMs);
    if (writeTimer && typeof writeTimer.unref === "function") {
      writeTimer.unref();
    }
  }

  async function flush() {
    return runExclusive(async () => {
      if (writeTimer) {
        clearTimeout(writeTimer);
        writeTimer = null;
      }

      let wrote = false;
      while (pendingEnvelope !== null) {
        const envelope = pendingEnvelope;
        pendingEnvelope = null;
        await writeAtomic(envelope);
        wrote = true;
      }

      return {
        ok: true,
        wrote,
      };
    }).catch((error) => ({
      ok: false,
      code: "STATE_FILE_WRITE_FAILED",
      message: error && typeof error.message === "string" ? error.message : "Failed to write state file",
    }));
  }

  async function close() {
    closed = true;
    return flush();
  }

  return {
    getPath: () => storePath,
    load,
    scheduleWrite,
    flush,
    close,
  };
}

module.exports = {
  createPersistentStore,
  CONTROL_PLANE_STATE_VERSION,
  DEFAULT_STORE_PATH,
};
