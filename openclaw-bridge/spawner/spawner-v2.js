const crypto = require("node:crypto");
const http = require("node:http");
const { spawn } = require("node:child_process");

const IMAGE_ALLOWLIST = Object.freeze({
  nmap: "openclaw-nmap-skill",
});

const DOCKER_NETWORK = "openclaw-net";
const CONTAINER_NAME_PREFIX = "openclaw-skill-";
const SKILL_EXECUTION_TIMEOUT_MS = 60000;
const HEALTH_TIMEOUT_MS = 15000;
const HEALTH_POLL_INTERVAL_MS = 500;
const HEALTH_REQUEST_TIMEOUT_MS = 2000;
const CONTAINER_HTTP_PORT = 4000;

const STATES = Object.freeze({
  CREATING: "CREATING",
  STARTING: "STARTING",
  READY: "READY",
  FAILED: "FAILED",
  TERMINATING: "TERMINATING",
  TERMINATED: "TERMINATED",
});

const NON_ZERO_STOP_OK = /is not running|No such container|No such object/i;
const NON_ZERO_RM_OK = /No such container|No such object/i;
const NON_ZERO_INSPECT_OK = /No such container|No such object/i;
const DOCKER_UNAVAILABLE_REGEX = /Cannot connect to the Docker daemon|Is the docker daemon running|error during connect|permission denied while trying to connect/i;

function createNoopMetrics() {
  return {
    increment: () => {},
    observe: () => {},
    gauge: () => {},
    snapshot: () => ({ counters: [], histograms: [], gauges: [] }),
    reset: () => {},
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
    snapshot: () => {
      try {
        if (typeof source.snapshot === "function") {
          return source.snapshot();
        }
      } catch {}
      return { counters: [], histograms: [], gauges: [] };
    },
    reset: () => {
      try {
        if (typeof source.reset === "function") {
          source.reset();
        }
      } catch {}
    },
  };
}

function createSpawnerV2(options = {}) {
  const registry = new Map();
  const metrics = createSafeMetrics(options.metrics);
  let initialized = false;

  function makeFailure(code, message, details) {
    const error = new Error(String(message || "Unexpected error"));
    error.code = String(code || "UNKNOWN_ERROR");
    if (typeof details !== "undefined") {
      error.details = details;
    }
    return error;
  }

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

  function toSafeError(error, fallbackCode, fallbackMessage) {
    if (error && typeof error === "object" && typeof error.code === "string" && typeof error.message === "string") {
      return safeError(error.code, error.message, error.details);
    }
    const message = error instanceof Error ? error.message : String(error || fallbackMessage || "Unexpected error");
    return safeError(fallbackCode || "UNKNOWN_ERROR", message);
  }

  function normalizeSlug(rawSlug) {
    return typeof rawSlug === "string" ? rawSlug.trim().toLowerCase() : "";
  }

  function maskToken(token) {
    const raw = typeof token === "string" ? token : "";
    if (raw.length <= 8) {
      return "***";
    }
    return `${raw.slice(0, 4)}...${raw.slice(-4)}`;
  }

  function makeToken() {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID().replace(/-/g, "");
    }
    return crypto.randomBytes(16).toString("hex");
  }

  function makeContainerName(slug) {
    const id = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
    return `${CONTAINER_NAME_PREFIX}${slug}-${id}`.toLowerCase();
  }

  function parseDockerIds(stdout) {
    return String(stdout || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  }

  function isDockerUnavailableOutput(stderr) {
    return DOCKER_UNAVAILABLE_REGEX.test(String(stderr || ""));
  }

  function runDocker(args, options = {}) {
    const allowNonZero = Boolean(options.allowNonZero);
    const errorCode = typeof options.errorCode === "string" ? options.errorCode : "DOCKER_ERROR";
    const errorMessage = typeof options.errorMessage === "string" ? options.errorMessage : "docker command failed";
    return new Promise((resolve, reject) => {
      const child = spawn("docker", args, {
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
      });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (chunk) => {
        stdout += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      });

      child.stderr.on("data", (chunk) => {
        stderr += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
      });

      child.on("error", (error) => {
        if (error && error.code === "ENOENT") {
          reject(makeFailure("DOCKER_UNAVAILABLE", "docker CLI is not available on PATH"));
          return;
        }
        reject(makeFailure("DOCKER_UNAVAILABLE", "docker invocation failed", { reason: String(error && error.message ? error.message : error) }));
      });

      child.on("close", (code) => {
        const exitCode = Number.isFinite(code) ? code : -1;
        if (exitCode !== 0 && !allowNonZero) {
          if (isDockerUnavailableOutput(stderr)) {
            reject(makeFailure("DOCKER_UNAVAILABLE", "Docker engine is unavailable"));
            return;
          }
          reject(
            makeFailure(errorCode, errorMessage, {
              exitCode,
              stderr: String(stderr || "").trim().slice(0, 500),
            }),
          );
          return;
        }
        resolve({ exitCode, stdout, stderr });
      });
    });
  }

  function setRegistryState(containerId, nextState, details = {}) {
    const entry = registry.get(containerId);
    if (!entry) {
      return null;
    }
    const updated = {
      ...entry,
      state: nextState,
      ...details,
    };
    registry.set(containerId, updated);
    return updated;
  }

  async function ensureNetworkExists() {
    const inspectResult = await runDocker(["network", "inspect", DOCKER_NETWORK], {
      allowNonZero: true,
    });

    if (inspectResult.exitCode === 0) {
      return;
    }

    if (isDockerUnavailableOutput(inspectResult.stderr)) {
      throw makeFailure("DOCKER_UNAVAILABLE", "Docker engine is unavailable");
    }

    const createResult = await runDocker(["network", "create", "--driver", "bridge", DOCKER_NETWORK], {
      allowNonZero: true,
    });

    if (createResult.exitCode === 0) {
      return;
    }

    const stderr = String(createResult.stderr || "");
    if (/already exists/i.test(stderr)) {
      return;
    }

    if (isDockerUnavailableOutput(stderr)) {
      throw makeFailure("DOCKER_UNAVAILABLE", "Docker engine is unavailable");
    }

    throw makeFailure("NETWORK_CREATE_FAILED", `Failed to create network '${DOCKER_NETWORK}'`, {
      stderr: stderr.trim().slice(0, 500),
    });
  }

  async function stopAndRemoveContainer(containerRef, failureCode, options = {}) {
    const force = Boolean(options.force);
    const stopResult = await runDocker(["stop", "-t", "5", containerRef], {
      allowNonZero: true,
    });
    const stopFailed = stopResult.exitCode !== 0 && !NON_ZERO_STOP_OK.test(String(stopResult.stderr || ""));
    if (stopFailed && !force) {
      throw makeFailure(failureCode, "Failed to stop container", {
        container: containerRef,
        stderr: String(stopResult.stderr || "").trim().slice(0, 500),
      });
    }

    const rmArgs = force ? ["rm", "-f", containerRef] : ["rm", containerRef];
    const rmResult = await runDocker(rmArgs, {
      allowNonZero: true,
    });
    if (rmResult.exitCode !== 0 && !NON_ZERO_RM_OK.test(String(rmResult.stderr || ""))) {
      throw makeFailure(failureCode, "Failed to remove container", {
        container: containerRef,
        stderr: String(rmResult.stderr || "").trim().slice(0, 500),
      });
    }
  }

  async function cleanupOrphansInternal() {
    const listResult = await runDocker(["ps", "-aq", "--filter", `name=${CONTAINER_NAME_PREFIX}`], {
      errorCode: "CLEANUP_FAILED",
      errorMessage: "Failed to list orphaned containers",
    });
    const containerIds = parseDockerIds(listResult.stdout);
    const removed = [];

    for (const containerId of containerIds) {
      const inspectPayload = await inspectContainer(containerId, { allowMissing: true });
      if (!inspectPayload) {
        continue;
      }
      const rawName = typeof inspectPayload.Name === "string" ? inspectPayload.Name : "";
      const normalizedName = rawName.startsWith("/") ? rawName.slice(1) : rawName;
      if (!normalizedName.startsWith(CONTAINER_NAME_PREFIX)) {
        continue;
      }
      await stopAndRemoveContainer(containerId, "CLEANUP_FAILED");
      removed.push(containerId);
    }

    return {
      ok: true,
      removed,
    };
  }

  async function inspectContainer(containerId, options = {}) {
    const allowMissing = Boolean(options.allowMissing);
    const result = await runDocker(["inspect", containerId], {
      allowNonZero: true,
    });

    if (result.exitCode !== 0) {
      const stderr = String(result.stderr || "");
      if (allowMissing && NON_ZERO_INSPECT_OK.test(stderr)) {
        return null;
      }
      throw makeFailure("INSPECT_FAILED", "Failed to inspect container", {
        containerId,
        stderr: stderr.trim().slice(0, 500),
      });
    }

    let parsed;
    try {
      parsed = JSON.parse(result.stdout);
    } catch (error) {
      throw makeFailure("INSPECT_FAILED", "docker inspect returned invalid JSON", {
        containerId,
        reason: String(error && error.message ? error.message : error),
      });
    }

    if (!Array.isArray(parsed) || parsed.length === 0 || typeof parsed[0] !== "object" || parsed[0] === null) {
      throw makeFailure("INSPECT_FAILED", "docker inspect payload was empty", { containerId });
    }

    return parsed[0];
  }

  async function getContainerIp(containerId) {
    const inspectPayload = await inspectContainer(containerId);
    const networks =
      inspectPayload &&
      inspectPayload.NetworkSettings &&
      inspectPayload.NetworkSettings.Networks &&
      typeof inspectPayload.NetworkSettings.Networks === "object"
        ? inspectPayload.NetworkSettings.Networks
        : null;

    if (!networks || !networks[DOCKER_NETWORK] || !networks[DOCKER_NETWORK].IPAddress) {
      return null;
    }

    return String(networks[DOCKER_NETWORK].IPAddress).trim() || null;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isValidJsonRpcEnvelope(parsed) {
    return (
      parsed &&
      typeof parsed === "object" &&
      parsed.jsonrpc === "2.0" &&
      Object.prototype.hasOwnProperty.call(parsed, "id") &&
      (Object.prototype.hasOwnProperty.call(parsed, "result") || Object.prototype.hasOwnProperty.call(parsed, "error"))
    );
  }

  function probeHealth(ipAddress, token) {
    return new Promise((resolve) => {
      const requestPayload = JSON.stringify({
        jsonrpc: "2.0",
        method: "health",
        params: {},
        id: `health-${crypto.randomBytes(4).toString("hex")}`,
      });

      const req = http.request(
        {
          host: ipAddress,
          port: CONTAINER_HTTP_PORT,
          path: "/mcp",
          method: "POST",
          timeout: HEALTH_REQUEST_TIMEOUT_MS,
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(requestPayload, "utf8"),
          },
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => {
            body += chunk;
          });
          res.on("end", () => {
            if (res.statusCode !== 200) {
              resolve({
                ok: false,
                reason: "http_status",
              });
              return;
            }

            try {
              const parsed = JSON.parse(body);
              if (!isValidJsonRpcEnvelope(parsed)) {
                resolve({
                  ok: false,
                  reason: "invalid_jsonrpc",
                });
                return;
              }
              if (Object.prototype.hasOwnProperty.call(parsed, "error")) {
                resolve({
                  ok: false,
                  reason: "rpc_error",
                });
                return;
              }
              resolve({
                ok: true,
                via: "ip_probe",
              });
            } catch {
              resolve({
                ok: false,
                reason: "invalid_json",
              });
            }
          });
        },
      );

      req.on("timeout", () => {
        req.destroy();
        resolve({
          ok: false,
          reason: "transport_timeout",
        });
      });

      req.on("error", () => {
        resolve({
          ok: false,
          reason: "transport_error",
        });
      });

      req.end(requestPayload);
    });
  }

  async function probeHealthByExec(containerRef, token) {
    const probeScript = [
      "const http=require('http');",
      "const payload=JSON.stringify({jsonrpc:'2.0',method:'health',params:{},id:'probe'});",
      "const req=http.request({host:'127.0.0.1',port:4000,path:'/mcp',method:'POST',timeout:1500,headers:{'Content-Type':'application/json','Authorization':`Bearer ${process.env.MCP_SKILL_TOKEN||''}`,'Content-Length':Buffer.byteLength(payload,'utf8')}},res=>{",
      "let body='';res.setEncoding('utf8');res.on('data',c=>body+=c);res.on('end',()=>{process.stdout.write(JSON.stringify({statusCode:res.statusCode,body}));});",
      "});",
      "req.on('timeout',()=>{process.stdout.write(JSON.stringify({transport:'timeout'}));req.destroy();});",
      "req.on('error',()=>{process.stdout.write(JSON.stringify({transport:'error'}));});",
      "req.end(payload);",
    ].join("");

    const execArgs = [
      "exec",
      "-e",
      `MCP_SKILL_TOKEN=${token}`,
      containerRef,
      "node",
      "-e",
      probeScript,
    ];

    const execResult = await runDocker(execArgs, {
      allowNonZero: true,
    });

    if (execResult.exitCode !== 0) {
      return {
        ok: false,
        reason: "exec_failed",
      };
    }

    const rawOutput = String(execResult.stdout || "").trim();
    if (!rawOutput) {
      return {
        ok: false,
        reason: "empty_exec_output",
      };
    }

    let wrapper;
    try {
      wrapper = JSON.parse(rawOutput);
    } catch {
      return {
        ok: false,
        reason: "invalid_exec_json",
      };
    }

    if (wrapper && wrapper.transport) {
      return {
        ok: false,
        reason: "exec_transport_error",
      };
    }

    if (!wrapper || wrapper.statusCode !== 200 || typeof wrapper.body !== "string") {
      return {
        ok: false,
        reason: "exec_http_status",
      };
    }

    let parsedBody;
    try {
      parsedBody = JSON.parse(wrapper.body);
    } catch {
      return {
        ok: false,
        reason: "exec_invalid_jsonrpc",
      };
    }

    if (!isValidJsonRpcEnvelope(parsedBody)) {
      return {
        ok: false,
        reason: "exec_invalid_jsonrpc",
      };
    }

    return {
      ok: true,
      via: "exec_probe",
    };
  }

  async function waitForReady(containerId, containerName, token, slug) {
    const deadline = Date.now() + HEALTH_TIMEOUT_MS;
    let lastInspectError = null;

    while (Date.now() < deadline) {
      let ipAddress = null;
      try {
        ipAddress = await getContainerIp(containerId);
      } catch (error) {
        lastInspectError = error;
      }

      if (ipAddress) {
        const primaryProbe = await probeHealth(ipAddress, token);
        if (primaryProbe.ok) {
          return ipAddress;
        }
        if (primaryProbe.reason === "transport_timeout" || primaryProbe.reason === "transport_error") {
          const fallbackProbe = await probeHealthByExec(containerName, token);
          if (fallbackProbe.ok) {
            return ipAddress;
          }
        }
      }

      await sleep(HEALTH_POLL_INTERVAL_MS);
    }

    if (lastInspectError) {
      throw makeFailure("HEALTHCHECK_FAILED", "Health check failed before timeout", {
        reason: lastInspectError.message,
      });
    }

    metrics.increment("spawner.health.timeout", { slug });
    throw makeFailure("HEALTHCHECK_TIMEOUT", `Container did not become healthy within ${HEALTH_TIMEOUT_MS}ms`);
  }

  async function initializeInternal() {
    if (initialized) {
      return {
        ok: true,
        initialized: true,
        network: DOCKER_NETWORK,
      };
    }

    await ensureNetworkExists();
    const cleanupResult = await cleanupOrphansInternal();

    initialized = true;

    return {
      ok: true,
      initialized: true,
      network: DOCKER_NETWORK,
      cleaned: cleanupResult.removed,
    };
  }

  async function spawnSkillInternal(rawSlug) {
    const slug = normalizeSlug(rawSlug);
    const image = IMAGE_ALLOWLIST[slug];
    if (!image) {
      throw makeFailure("INVALID_SLUG", `Slug '${String(rawSlug || "")}' is not allowed`);
    }

    if (!initialized) {
      await initializeInternal();
    }

    const spawnStartedAt = Date.now();
    metrics.increment("spawner.spawn.attempt", { slug });

    const token = makeToken();
    const name = makeContainerName(slug);

    const runArgs = [
      "run",
      "-d",
      "--name",
      name,
      "--network",
      DOCKER_NETWORK,
      "--cap-drop",
      "ALL",
      "--memory",
      "512m",
      "--cpus",
      "1",
      "--pids-limit",
      "128",
      "--read-only",
      "--security-opt",
      "no-new-privileges",
      "-e",
      `MCP_SKILL_TOKEN=${token}`,
      "-e",
      `SKILL_EXECUTION_TIMEOUT_MS=${SKILL_EXECUTION_TIMEOUT_MS}`,
      "-e",
      `TOOL_NAME=${slug}`,
      "-e",
      `SKILL_SLUG=${slug}`,
      image,
    ];

    const runResult = await runDocker(runArgs, {
      allowNonZero: true,
    });

    if (runResult.exitCode !== 0) {
      throw makeFailure("SPAWN_FAILED", "Failed to start skill container", {
        slug,
        stderr: String(runResult.stderr || "").trim().slice(0, 500),
      });
    }

    const containerId = String(runResult.stdout || "").trim().split(/\r?\n/)[0];
    if (!containerId) {
      throw makeFailure("SPAWN_FAILED", "Docker did not return a container ID");
    }

    registry.set(containerId, {
      slug,
      token,
      state: STATES.CREATING,
      createdAt: Date.now(),
      name,
      networkAddress: null,
      lastError: null,
    });

    setRegistryState(containerId, STATES.STARTING);

    try {
      const ipAddress = await waitForReady(containerId, name, token, slug);
      const networkAddress = `http://${ipAddress}:${CONTAINER_HTTP_PORT}/mcp`;
      setRegistryState(containerId, STATES.READY, {
        networkAddress,
        lastError: null,
      });
      metrics.increment("spawner.spawn.success", { slug });
      return {
        containerId,
        name,
        slug,
        networkAddress,
        token,
        state: STATES.READY,
      };
    } catch (error) {
      metrics.increment("spawner.spawn.failure", { slug });
      setRegistryState(containerId, STATES.FAILED, {
        lastError: error && error.message ? String(error.message) : "Health check failed",
      });
      try {
        await stopAndRemoveContainer(containerId, "HEALTHCHECK_FAILED", { force: true });
        setRegistryState(containerId, STATES.FAILED, {
          token: "",
        });
      } catch (cleanupError) {
        setRegistryState(containerId, STATES.FAILED, {
          lastError: `${error && error.message ? error.message : "Health check failed"}; cleanup: ${
            cleanupError && cleanupError.message ? cleanupError.message : "unknown cleanup error"
          }`,
        });
      }
      throw error;
    } finally {
      metrics.observe("spawner.spawn.duration_ms", Date.now() - spawnStartedAt, { slug });
    }
  }

  function cloneEntry(containerId, entry) {
    return {
      containerId,
      slug: entry.slug,
      token_hint: maskToken(entry.token),
      state: entry.state,
      createdAt: entry.createdAt,
      name: entry.name,
      networkAddress: entry.networkAddress,
      lastError: entry.lastError,
    };
  }

  async function terminateSkillInternal(containerId) {
    const key = typeof containerId === "string" ? containerId.trim() : "";
    if (!key) {
      metrics.increment("spawner.terminate.failure", { slug: "unknown" });
      throw makeFailure("CONTAINER_NOT_FOUND", "containerId is required");
    }

    const entry = registry.get(key);
    if (!entry) {
      metrics.increment("spawner.terminate.failure", { slug: "unknown" });
      throw makeFailure("CONTAINER_NOT_FOUND", "containerId is not tracked by spawner", {
        containerId: key,
      });
    }

    setRegistryState(key, STATES.TERMINATING, { lastError: null });

    try {
      await stopAndRemoveContainer(key, "TERMINATE_FAILED");
      const updated = setRegistryState(key, STATES.TERMINATED, {
        token: "",
        networkAddress: null,
        lastError: null,
      });
      metrics.increment("spawner.terminate.success", { slug: entry.slug });
      return {
        ok: true,
        containerId: key,
        name: entry.name,
        slug: entry.slug,
        state: updated ? updated.state : STATES.TERMINATED,
      };
    } catch (error) {
      metrics.increment("spawner.terminate.failure", { slug: entry.slug });
      setRegistryState(key, STATES.FAILED, {
        lastError: error && error.message ? String(error.message) : "Termination failed",
      });
      throw error;
    }
  }

  async function getSkillStateInternal(containerId) {
    const key = typeof containerId === "string" ? containerId.trim() : "";
    if (!key) {
      throw makeFailure("CONTAINER_NOT_FOUND", "containerId is required");
    }
    const entry = registry.get(key);
    if (!entry) {
      throw makeFailure("CONTAINER_NOT_FOUND", "containerId is not tracked by spawner", {
        containerId: key,
      });
    }
    return {
      ok: true,
      state: cloneEntry(key, entry),
    };
  }

  async function listSkillStatesInternal() {
    const states = Array.from(registry.entries())
      .map(([containerId, entry]) => cloneEntry(containerId, entry))
      .sort((a, b) => {
        if (a.createdAt !== b.createdAt) {
          return a.createdAt - b.createdAt;
        }
        return a.containerId.localeCompare(b.containerId);
      });

    return {
      ok: true,
      states,
    };
  }

  function wrap(handler, fallbackCode, fallbackMessage) {
    return async (...args) => {
      try {
        return await handler(...args);
      } catch (error) {
        return toSafeError(error, fallbackCode, fallbackMessage);
      }
    };
  }

  return {
    initialize: wrap(initializeInternal, "SPAWNER_INIT_FAILED", "Spawner initialization failed"),
    spawnSkill: wrap(spawnSkillInternal, "SPAWN_FAILED", "Failed to spawn skill container"),
    terminateSkill: wrap(terminateSkillInternal, "TERMINATE_FAILED", "Failed to terminate skill container"),
    getSkillState: wrap(getSkillStateInternal, "GET_STATE_FAILED", "Failed to fetch skill state"),
    listSkillStates: wrap(listSkillStatesInternal, "LIST_STATES_FAILED", "Failed to list skill states"),
    cleanupOrphans: wrap(cleanupOrphansInternal, "CLEANUP_FAILED", "Failed to cleanup orphaned containers"),
    constants: {
      IMAGE_ALLOWLIST,
      DOCKER_NETWORK,
      CONTAINER_NAME_PREFIX,
      STATES,
      HEALTH_TIMEOUT_MS,
      HEALTH_POLL_INTERVAL_MS,
      SKILL_EXECUTION_TIMEOUT_MS,
      CONTAINER_HTTP_PORT,
    },
  };
}

module.exports = {
  createSpawnerV2,
};
