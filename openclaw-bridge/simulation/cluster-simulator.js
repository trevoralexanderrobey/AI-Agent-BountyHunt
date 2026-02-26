"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { AsyncLocalStorage } = require("node:async_hooks");
const http = require("node:http");
const https = require("node:https");

const { createMetrics } = require("../observability/metrics.js");
const { createPeerRegistry, STATUS_UP, STATUS_DOWN } = require("../federation/peer-registry.js");
const { createHttpHandlers } = require("../http/handlers.js");
const { createRequestSigner } = require("../security/request-signing.js");
const { createFaultInjector } = require("./fault-injector.js");

const DEFAULT_NODE_COUNT = 6;
const DEFAULT_SOFTWARE_VERSION = "1.0.0";
const DEFAULT_SHARD_COUNT = 16;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 5000;
const DEFAULT_LEADER_TIMEOUT_MS = 15000;
const DEFAULT_CONVERGENCE_WINDOW_MS = 10000;
const DEFAULT_QUEUE_POLL_INTERVAL_MS = 250;
const DEFAULT_CLOCK_START_MS = Date.UTC(2026, 0, 1, 0, 0, 0);
const DEFAULT_RANDOM_SEED = 424242;

function normalizeNodeId(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizePositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function normalizeNonNegativeInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function normalizeBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
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

function normalizeHeaders(rawHeaders) {
  const normalized = {};
  if (!rawHeaders || typeof rawHeaders !== "object") {
    return normalized;
  }
  for (const key of Object.keys(rawHeaders)) {
    const lower = String(key || "").toLowerCase();
    if (!lower) {
      continue;
    }
    const value = rawHeaders[key];
    if (typeof value === "undefined" || value === null) {
      continue;
    }
    normalized[lower] = Array.isArray(value) ? value.map((item) => String(item)) : String(value);
  }
  return normalized;
}

function getBaseContentType(rawHeader) {
  if (typeof rawHeader !== "string") {
    return "";
  }
  return rawHeader.split(";")[0].trim().toLowerCase();
}

function hashStable(value) {
  const stringify = (input) => {
    if (Array.isArray(input)) {
      return `[${input.map((item) => stringify(item)).join(",")}]`;
    }
    if (input && typeof input === "object") {
      const keys = Object.keys(input).sort((a, b) => a.localeCompare(b));
      return `{${keys.map((key) => `${JSON.stringify(key)}:${stringify(input[key])}`).join(",")}}`;
    }
    return JSON.stringify(input);
  };
  return crypto.createHash("sha256").update(stringify(value), "utf8").digest("hex");
}

function deepClone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function pickRandom(prng, values) {
  if (!Array.isArray(values) || values.length === 0) {
    return null;
  }
  const index = Math.floor(prng() * values.length);
  return values[index];
}

function createDeterministicPrng(seedValue) {
  let state = normalizePositiveInt(seedValue, DEFAULT_RANDOM_SEED) >>> 0;
  return function nextRandom() {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function createDeterministicClock(options = {}) {
  const contextStore = options.contextStore;
  const runWithContext = typeof options.runWithContext === "function" ? options.runWithContext : (_, fn) => fn();
  let nowMs = normalizeNonNegativeInt(options.startMs, DEFAULT_CLOCK_START_MS);
  let nextTimerId = 1;
  const timers = new Map();
  const timerErrors = [];

  function currentContextSnapshot() {
    if (!contextStore || typeof contextStore.getStore !== "function") {
      return null;
    }
    const current = contextStore.getStore();
    if (!current || typeof current !== "object") {
      return null;
    }
    return { ...current };
  }

  function normalizeTimerDelay(rawDelay) {
    const parsed = Number(rawDelay);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return 0;
    }
    return Math.floor(parsed);
  }

  function makeHandle(timerId) {
    return {
      _timerId: timerId,
      _refed: true,
      unref() {
        this._refed = false;
        return this;
      },
      ref() {
        this._refed = true;
        return this;
      },
      hasRef() {
        return this._refed !== false;
      },
    };
  }

  function getTimerId(rawHandle) {
    if (rawHandle && typeof rawHandle === "object" && Number.isFinite(Number(rawHandle._timerId))) {
      return Number(rawHandle._timerId);
    }
    if (Number.isFinite(Number(rawHandle))) {
      return Number(rawHandle);
    }
    return 0;
  }

  function scheduleTimer(kind, callback, delay, args, intervalMs = 0) {
    if (typeof callback !== "function") {
      throw new TypeError(`${kind} callback must be a function`);
    }
    const timerId = nextTimerId++;
    const dueAt = nowMs + normalizeTimerDelay(delay);
    const handle = makeHandle(timerId);

    timers.set(timerId, {
      id: timerId,
      kind,
      dueAt,
      callback,
      args: Array.isArray(args) ? args : [],
      intervalMs: normalizeTimerDelay(intervalMs),
      repeat: kind === "interval",
      canceled: false,
      handle,
      context: currentContextSnapshot(),
    });

    return handle;
  }

  function clearTimer(rawHandle) {
    const timerId = getTimerId(rawHandle);
    if (!timerId) {
      return;
    }
    const timer = timers.get(timerId);
    if (!timer) {
      return;
    }
    timer.canceled = true;
    timers.delete(timerId);
  }

  function getNextDueTimer(targetMs) {
    let selected = null;
    for (const timer of timers.values()) {
      if (timer.canceled) {
        continue;
      }
      if (timer.dueAt > targetMs) {
        continue;
      }
      if (!selected || timer.dueAt < selected.dueAt || (timer.dueAt === selected.dueAt && timer.id < selected.id)) {
        selected = timer;
      }
    }
    return selected;
  }

  function runTimer(timer) {
    if (!timer || timer.canceled) {
      return;
    }

    if (timer.repeat) {
      timer.dueAt = nowMs + Math.max(1, timer.intervalMs);
      timers.set(timer.id, timer);
    } else {
      timers.delete(timer.id);
    }

    const invoke = () => {
      timer.callback(...timer.args);
    };

    try {
      if (timer.context) {
        runWithContext(timer.context, invoke);
      } else {
        invoke();
      }
    } catch (error) {
      timerErrors.push({
        timerId: timer.id,
        message: error && typeof error.message === "string" ? error.message : "timer callback error",
      });
    }
  }

  function advance(ms) {
    const stepMs = normalizeTimerDelay(ms);
    const targetMs = nowMs + stepMs;

    while (true) {
      const nextTimer = getNextDueTimer(targetMs);
      if (!nextTimer) {
        break;
      }
      nowMs = nextTimer.dueAt;
      runTimer(nextTimer);
    }

    nowMs = targetMs;
    return nowMs;
  }

  function sleep(ms) {
    return new Promise((resolve) => {
      scheduleTimer("timeout", resolve, ms, []);
    });
  }

  return {
    now: () => nowMs,
    setTimeout: (callback, delay, ...args) => scheduleTimer("timeout", callback, delay, args),
    clearTimeout: clearTimer,
    setInterval: (callback, delay, ...args) => scheduleTimer("interval", callback, delay, args, delay),
    clearInterval: clearTimer,
    advance,
    sleep,
    getPendingTimerCount: () => timers.size,
    getTimerErrors: () => timerErrors.slice(),
  };
}

function installDeterministicTimeEnvironment(clock) {
  const realDate = global.Date;
  const realSetTimeout = global.setTimeout;
  const realClearTimeout = global.clearTimeout;
  const realSetInterval = global.setInterval;
  const realClearInterval = global.clearInterval;
  const realSetImmediate = global.setImmediate;
  const realClearImmediate = global.clearImmediate;
  const timersModule = require("node:timers");
  const realTimersSetTimeout = timersModule.setTimeout;
  const realTimersClearTimeout = timersModule.clearTimeout;
  const realTimersSetInterval = timersModule.setInterval;
  const realTimersClearInterval = timersModule.clearInterval;
  const realTimersSetImmediate = timersModule.setImmediate;
  const realTimersClearImmediate = timersModule.clearImmediate;

  class SimulatedDate extends realDate {
    constructor(...args) {
      if (args.length === 0) {
        super(clock.now());
      } else {
        super(...args);
      }
    }

    static now() {
      return clock.now();
    }
  }

  SimulatedDate.UTC = realDate.UTC;
  SimulatedDate.parse = realDate.parse;

  global.Date = SimulatedDate;
  global.setTimeout = (...args) => clock.setTimeout(...args);
  global.clearTimeout = (handle) => clock.clearTimeout(handle);
  global.setInterval = (...args) => clock.setInterval(...args);
  global.clearInterval = (handle) => clock.clearInterval(handle);
  global.setImmediate = (callback, ...args) => clock.setTimeout(callback, 0, ...args);
  global.clearImmediate = (handle) => clock.clearTimeout(handle);

  timersModule.setTimeout = (...args) => clock.setTimeout(...args);
  timersModule.clearTimeout = (handle) => clock.clearTimeout(handle);
  timersModule.setInterval = (...args) => clock.setInterval(...args);
  timersModule.clearInterval = (handle) => clock.clearInterval(handle);
  timersModule.setImmediate = (callback, ...args) => clock.setTimeout(callback, 0, ...args);
  timersModule.clearImmediate = (handle) => clock.clearTimeout(handle);

  return () => {
    global.Date = realDate;
    global.setTimeout = realSetTimeout;
    global.clearTimeout = realClearTimeout;
    global.setInterval = realSetInterval;
    global.clearInterval = realClearInterval;
    global.setImmediate = realSetImmediate;
    global.clearImmediate = realClearImmediate;
    timersModule.setTimeout = realTimersSetTimeout;
    timersModule.clearTimeout = realTimersClearTimeout;
    timersModule.setInterval = realTimersSetInterval;
    timersModule.clearInterval = realTimersClearInterval;
    timersModule.setImmediate = realTimersSetImmediate;
    timersModule.clearImmediate = realTimersClearImmediate;
  };
}

class MockIncomingMessage extends EventEmitter {
  constructor(response) {
    super();
    this.statusCode = normalizeNonNegativeInt(response && response.statusCode, 200);
    this.headers = normalizeHeaders(response && response.headers);
    this._body = typeof (response && response.body) === "string" ? response.body : "";
    this._encoding = "utf8";
  }

  setEncoding(encoding) {
    this._encoding = typeof encoding === "string" && encoding ? encoding : "utf8";
  }

  begin() {
    if (this._body.length > 0) {
      this.emit("data", this._body);
    }
    this.emit("end");
  }
}

class MockClientRequest extends EventEmitter {
  constructor(options) {
    super();
    this.clock = options.clock;
    this.dispatch = options.dispatch;
    this.request = options.request;
    this.responseCallback = typeof options.responseCallback === "function" ? options.responseCallback : null;
    this.bodyChunks = [];
    this.finished = false;
    this.destroyed = false;
    this.completed = false;
    this.timeoutHandle = null;

    const initialTimeout = normalizePositiveInt(this.request.timeout, 0);
    if (initialTimeout > 0) {
      this.setTimeout(initialTimeout);
    }
  }

  write(chunk) {
    if (this.finished || this.destroyed) {
      return false;
    }
    if (typeof chunk === "undefined" || chunk === null) {
      return true;
    }
    if (Buffer.isBuffer(chunk)) {
      this.bodyChunks.push(chunk.toString("utf8"));
      return true;
    }
    this.bodyChunks.push(String(chunk));
    return true;
  }

  end(chunk) {
    if (typeof chunk !== "undefined" && chunk !== null) {
      this.write(chunk);
    }
    if (this.finished || this.destroyed) {
      return;
    }
    this.finished = true;
    this.dispatch(this, {
      ...this.request,
      body: this.bodyChunks.join(""),
    }).catch((error) => {
      this._emitError(error);
    });
  }

  setTimeout(timeoutMs, callback) {
    if (typeof callback === "function") {
      this.once("timeout", callback);
    }

    const timeout = normalizePositiveInt(timeoutMs, 0);
    if (this.timeoutHandle) {
      this.clock.clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }

    if (timeout <= 0 || this.completed || this.destroyed) {
      return this;
    }

    this.timeoutHandle = this.clock.setTimeout(() => {
      if (this.completed || this.destroyed) {
        return;
      }
      this.emit("timeout");
    }, timeout);

    return this;
  }

  destroy(error) {
    if (this.completed || this.destroyed) {
      return this;
    }
    this.destroyed = true;
    if (this.timeoutHandle) {
      this.clock.clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }
    const reason = error instanceof Error ? error : new Error("request destroyed");
    this.emit("error", reason);
    return this;
  }

  _emitError(error) {
    if (this.completed || this.destroyed) {
      return;
    }
    this.destroy(error);
  }

  _respond(response) {
    if (this.completed || this.destroyed) {
      return;
    }
    this.completed = true;
    if (this.timeoutHandle) {
      this.clock.clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }

    const message = new MockIncomingMessage(response);
    if (this.responseCallback) {
      this.responseCallback(message);
    }
    this.emit("response", message);
    message.begin();
  }
}

class MockIncomingRequest extends EventEmitter {
  constructor(options) {
    super();
    this.method = options.method;
    this.url = options.url;
    this.headers = normalizeHeaders(options.headers);
    this.httpVersion = "1.1";
    this.socket = {};
    this.connection = this.socket;
    this._body = typeof options.body === "string" ? options.body : "";
    this._destroyed = false;
  }

  setEncoding() {}

  start() {
    if (this._destroyed) {
      return;
    }
    if (this._body.length > 0) {
      this.emit("data", this._body);
    }
    this.emit("end");
  }

  destroy() {
    this._destroyed = true;
    this.emit("error", new Error("request destroyed"));
  }
}

class MockServerResponse extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headersSent = false;
    this.finished = false;
    this._headers = {};
    this._chunks = [];
  }

  setHeader(name, value) {
    const key = String(name || "").toLowerCase();
    if (!key) {
      return;
    }
    this._headers[key] = String(value);
  }

  getHeader(name) {
    const key = String(name || "").toLowerCase();
    return this._headers[key];
  }

  writeHead(statusCode, headers = {}) {
    this.statusCode = normalizeNonNegativeInt(statusCode, this.statusCode);
    const normalized = normalizeHeaders(headers);
    for (const key of Object.keys(normalized)) {
      this._headers[key] = normalized[key];
    }
    this.headersSent = true;
  }

  write(chunk) {
    if (this.finished) {
      return false;
    }
    if (typeof chunk === "undefined" || chunk === null) {
      return true;
    }
    if (Buffer.isBuffer(chunk)) {
      this._chunks.push(chunk.toString("utf8"));
      return true;
    }
    this._chunks.push(String(chunk));
    return true;
  }

  end(chunk) {
    if (typeof chunk !== "undefined" && chunk !== null) {
      this.write(chunk);
    }
    if (this.finished) {
      return;
    }
    this.finished = true;
    this.headersSent = true;
    this.emit("finish");
  }

  getBody() {
    return this._chunks.join("");
  }

  getHeaders() {
    return { ...this._headers };
  }
}

function writeApiError(statusCode, code, message) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ok: false,
      error: {
        code,
        message,
      },
      api_version: "v1",
      timestamp: new Date().toISOString(),
    }),
  };
}

function normalizeRequestInvocation(args, defaultProtocol) {
  if (!Array.isArray(args) || args.length === 0) {
    return null;
  }

  let callback = null;
  for (const item of args) {
    if (typeof item === "function") {
      callback = item;
      break;
    }
  }

  let requestInput = null;
  if (args[0] instanceof URL) {
    requestInput = args[0];
  } else if (typeof args[0] === "string") {
    requestInput = args[0];
  } else if (args[0] && typeof args[0] === "object") {
    requestInput = args[0];
  }

  const optionsInput =
    args.length > 1 && args[1] && typeof args[1] === "object" && !(args[1] instanceof URL) && typeof args[1] !== "function"
      ? args[1]
      : null;

  let protocol = defaultProtocol;
  let hostname = "";
  let port = "";
  let pathName = "/";
  let method = "GET";
  let headers = {};
  let timeout = 0;

  if (requestInput instanceof URL || typeof requestInput === "string") {
    let parsed;
    try {
      parsed = requestInput instanceof URL ? requestInput : new URL(String(requestInput));
    } catch {
      return null;
    }
    protocol = parsed.protocol || protocol;
    hostname = parsed.hostname || "";
    port = parsed.port || "";
    pathName = `${parsed.pathname || "/"}${parsed.search || ""}`;
    method = "GET";
    headers = {};
    timeout = 0;
  } else if (requestInput && typeof requestInput === "object") {
    protocol = typeof requestInput.protocol === "string" ? requestInput.protocol : protocol;
    hostname = typeof requestInput.hostname === "string" ? requestInput.hostname : requestInput.host || "";
    port =
      typeof requestInput.port !== "undefined" && requestInput.port !== null && String(requestInput.port).trim().length > 0
        ? String(requestInput.port).trim()
        : "";
    pathName = typeof requestInput.path === "string" && requestInput.path ? requestInput.path : "/";
    method = typeof requestInput.method === "string" && requestInput.method ? requestInput.method.toUpperCase() : "GET";
    headers = normalizeHeaders(requestInput.headers);
    timeout = normalizeNonNegativeInt(requestInput.timeout, 0);
  } else {
    return null;
  }

  if (optionsInput) {
    if (typeof optionsInput.protocol === "string") {
      protocol = optionsInput.protocol;
    }
    if (typeof optionsInput.hostname === "string") {
      hostname = optionsInput.hostname;
    }
    if (typeof optionsInput.host === "string" && !hostname) {
      hostname = optionsInput.host;
    }
    if (
      typeof optionsInput.port !== "undefined" &&
      optionsInput.port !== null &&
      String(optionsInput.port).trim().length > 0
    ) {
      port = String(optionsInput.port).trim();
    }
    if (typeof optionsInput.path === "string" && optionsInput.path) {
      pathName = optionsInput.path;
    }
    if (typeof optionsInput.method === "string" && optionsInput.method) {
      method = optionsInput.method.toUpperCase();
    }
    headers = {
      ...headers,
      ...normalizeHeaders(optionsInput.headers),
    };
    timeout = normalizeNonNegativeInt(optionsInput.timeout, timeout);
  }

  const normalizedProtocol = protocol === "https:" ? "https:" : "http:";
  const normalizedHost = String(hostname || "").trim().toLowerCase();
  if (!normalizedHost) {
    return null;
  }
  const normalizedPort = port || (normalizedProtocol === "https:" ? "443" : "80");

  return {
    callback,
    request: {
      protocol: normalizedProtocol,
      hostname: normalizedHost,
      port: normalizedPort,
      path: pathName || "/",
      method: method || "GET",
      headers,
      timeout,
    },
  };
}

function createInMemoryTransport(options = {}) {
  const contextStore = options.contextStore;
  const runWithContext = typeof options.runWithContext === "function" ? options.runWithContext : (_, fn) => fn();
  const clock = options.clock;
  const faultInjector = options.faultInjector;
  const trace = typeof options.trace === "function" ? options.trace : () => {};
  const nodeByHostPort = new Map();
  const runtimeByHostPort = new Map();
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  let patched = false;

  function endpointKey(protocol, hostname, port) {
    return `${protocol}//${hostname}:${port}`;
  }

  function registerNodeEndpoint(config) {
    const protocol = config.protocol === "https:" ? "https:" : "http:";
    const hostname = String(config.hostname || "").trim().toLowerCase();
    const port = String(config.port || (protocol === "https:" ? "443" : "80")).trim();
    if (!hostname) {
      throw new Error("registerNodeEndpoint requires hostname");
    }
    const key = endpointKey(protocol, hostname, port);
    nodeByHostPort.set(key, {
      nodeId: normalizeNodeId(config.nodeId),
      handler: config.handler,
      requestSigner: config.requestSigner,
      allowAutoSign: config.allowAutoSign !== false,
      softwareVersion: config.softwareVersion || "",
      configHash: config.configHash || "",
      meta: config.meta || {},
    });
    return key;
  }

  function unregisterNodeEndpoint(config) {
    const protocol = config.protocol === "https:" ? "https:" : "http:";
    const hostname = String(config.hostname || "").trim().toLowerCase();
    const port = String(config.port || (protocol === "https:" ? "443" : "80")).trim();
    const key = endpointKey(protocol, hostname, port);
    nodeByHostPort.delete(key);
  }

  function registerRuntimeEndpoint(config) {
    const protocol = config.protocol === "https:" ? "https:" : "http:";
    const hostname = String(config.hostname || "").trim().toLowerCase();
    const port = String(config.port || (protocol === "https:" ? "443" : "80")).trim();
    if (!hostname) {
      throw new Error("registerRuntimeEndpoint requires hostname");
    }
    const key = endpointKey(protocol, hostname, port);
    runtimeByHostPort.set(key, {
      ownerNodeId: normalizeNodeId(config.ownerNodeId),
      handler: config.handler,
    });
    return key;
  }

  function unregisterRuntimeEndpoint(config) {
    const protocol = config.protocol === "https:" ? "https:" : "http:";
    const hostname = String(config.hostname || "").trim().toLowerCase();
    const port = String(config.port || (protocol === "https:" ? "443" : "80")).trim();
    const key = endpointKey(protocol, hostname, port);
    runtimeByHostPort.delete(key);
  }

  function lookupEndpoint(request) {
    const key = endpointKey(request.protocol, request.hostname, request.port);
    if (nodeByHostPort.has(key)) {
      return {
        kind: "node",
        key,
        value: nodeByHostPort.get(key),
      };
    }
    if (runtimeByHostPort.has(key)) {
      return {
        kind: "runtime",
        key,
        value: runtimeByHostPort.get(key),
      };
    }
    return null;
  }

  async function dispatchClientRequest(clientRequest, request) {
    const endpoint = lookupEndpoint(request);
    if (!endpoint) {
      clientRequest._emitError(new Error(`connect ECONNREFUSED ${request.hostname}:${request.port}`));
      return;
    }

    const context = contextStore && typeof contextStore.getStore === "function" ? contextStore.getStore() : null;
    const sourceNodeId = normalizeNodeId(context && context.nodeId);
    const requestIdHeader = request.headers["x-request-id"];
    const requestId =
      typeof requestIdHeader === "string"
        ? requestIdHeader
        : Array.isArray(requestIdHeader) && requestIdHeader.length > 0
        ? String(requestIdHeader[0])
        : "";
    const targetNodeId = endpoint.kind === "node" ? normalizeNodeId(endpoint.value.nodeId) : normalizeNodeId(endpoint.value.ownerNodeId);

    const networkFault = faultInjector.evaluateRequest({
      sourceNodeId,
      targetNodeId,
      path: request.path,
      method: request.method,
    });

    trace({
      type: "transport_dispatch",
      requestId,
      sourceNodeId,
      targetNodeId,
      path: request.path,
      method: request.method,
      timeoutInjected: networkFault.timeout,
      statusOverride: networkFault.statusCode || null,
      latencyMs: networkFault.latencyMs || 0,
    });

    if (networkFault.timeout) {
      // Intentionally no response. Callers with setTimeout/timeout handlers will drive timeout behavior.
      return;
    }

    if (networkFault.latencyMs > 0) {
      await clock.sleep(networkFault.latencyMs);
      if (clientRequest.destroyed || clientRequest.completed) {
        return;
      }
    }

    if (networkFault.statusCode) {
      clientRequest._respond(
        writeApiError(
          networkFault.statusCode,
          networkFault.statusCode === 429 ? "RATE_LIMIT_EXCEEDED" : "INTERNAL_ERROR",
          `Injected HTTP ${networkFault.statusCode}`,
        ),
      );
      return;
    }

    const invoke = async () => {
      if (endpoint.kind === "runtime") {
        return endpoint.value.handler({
          method: request.method,
          path: request.path,
          headers: request.headers,
          body: request.body || "",
          sourceNodeId,
          targetNodeId,
        });
      }
      return endpoint.value.handler({
        method: request.method,
        path: request.path,
        headers: request.headers,
        body: request.body || "",
        sourceNodeId,
        targetNodeId,
        requestSigner: endpoint.value.requestSigner,
        allowAutoSign: endpoint.value.allowAutoSign,
      });
    };

    let response;
    try {
      response = await runWithContext(
        {
          nodeId: targetNodeId || sourceNodeId || "",
          requestId,
          sourceNodeId,
        },
        invoke,
      );
    } catch (error) {
      clientRequest._emitError(error);
      return;
    }

    clientRequest._respond({
      statusCode: normalizeNonNegativeInt(response && response.statusCode, 200),
      headers: normalizeHeaders(response && response.headers),
      body: typeof (response && response.body) === "string" ? response.body : "",
    });
  }

  function installPatches() {
    if (patched) {
      return;
    }
    patched = true;

    http.request = function patchedHttpRequest(...args) {
      const normalized = normalizeRequestInvocation(args, "http:");
      if (!normalized) {
        return originalHttpRequest.apply(http, args);
      }

      const endpoint = lookupEndpoint(normalized.request);
      if (!endpoint) {
        return originalHttpRequest.apply(http, args);
      }

      return new MockClientRequest({
        clock,
        request: normalized.request,
        responseCallback: normalized.callback,
        dispatch: dispatchClientRequest,
      });
    };

    https.request = function patchedHttpsRequest(...args) {
      const normalized = normalizeRequestInvocation(args, "https:");
      if (!normalized) {
        return originalHttpsRequest.apply(https, args);
      }

      const endpoint = lookupEndpoint(normalized.request);
      if (!endpoint) {
        return originalHttpsRequest.apply(https, args);
      }

      return new MockClientRequest({
        clock,
        request: normalized.request,
        responseCallback: normalized.callback,
        dispatch: dispatchClientRequest,
      });
    };
  }

  function restorePatches() {
    if (!patched) {
      return;
    }
    patched = false;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
  }

  return {
    registerNodeEndpoint,
    unregisterNodeEndpoint,
    registerRuntimeEndpoint,
    unregisterRuntimeEndpoint,
    installPatches,
    restorePatches,
  };
}

function createSimulationToolAdapter(nodeId, clock, trace) {
  return {
    name: "simulation-tool",
    slug: "sim-tool",
    description: "Deterministic in-process simulation tool adapter",
    async validateInput(params) {
      if (!params || typeof params !== "object" || Array.isArray(params)) {
        return {
          valid: false,
          errors: ["params must be an object"],
        };
      }
      return {
        valid: true,
        errors: [],
      };
    },
    normalizeOutput(result) {
      return result;
    },
    getResourceLimits() {
      return {
        timeoutMs: 60000,
        maxOutputBytes: 1024 * 1024,
      };
    },
    async execute(request = {}) {
      const params = request && request.params && typeof request.params === "object" ? request.params : {};
      const delayMs = normalizeNonNegativeInt(params.delayMs, 0);
      const startedAt = clock.now();
      if (delayMs > 0) {
        await clock.sleep(delayMs);
      }

      const result = {
        ok: true,
        result: {
          nodeId,
          tool: "sim-tool",
          echoed: deepClone(params),
          requestId: request.requestId || "",
          timestamp: clock.now(),
        },
        metadata: {
          executionTimeMs: Math.max(0, clock.now() - startedAt),
          outputBytes: Buffer.byteLength(JSON.stringify(params), "utf8"),
          requestId: request.requestId || "",
        },
      };

      trace({
        type: "tool_execute",
        nodeId,
        requestId: request.requestId || "",
        startedAt,
        endedAt: clock.now(),
      });

      return result;
    },
  };
}

function createFakeSpawnerFactory(simulationState, nodeRuntime) {
  let containerSequence = 0;
  const instances = new Map();
  const failureOnceKeys = new Set();

  const clock = simulationState.clock;
  const transport = simulationState.transport;
  const trace = simulationState.trace;

  function createRuntimeHandler(instance) {
    return async (request) => {
      const authHeader = request && request.headers ? request.headers.authorization : "";
      if (typeof authHeader !== "string" || authHeader.trim() !== `Bearer ${instance.token}`) {
        return {
          statusCode: 401,
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ok: false,
            error: {
              code: "UNAUTHORIZED",
              message: "Authentication failed",
            },
          }),
        };
      }

      if (request.path !== "/rpc" || request.method !== "POST") {
        return {
          statusCode: 404,
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ok: false,
            error: {
              code: "INVALID_REQUEST",
              message: "Route not found",
            },
          }),
        };
      }

      let payload = {};
      try {
        payload = request.body ? JSON.parse(request.body) : {};
      } catch {
        return {
          statusCode: 400,
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ok: false,
            error: {
              code: "INVALID_REQUEST",
              message: "Invalid JSON body",
            },
          }),
        };
      }

      const rpcMethod = typeof payload.method === "string" ? payload.method : "";
      const params = payload && payload.params && typeof payload.params === "object" ? payload.params : {};
      const requestId = typeof payload.id !== "undefined" ? payload.id : "";

      if (params && params.__simulate_transport_failure_always === true) {
        return {
          statusCode: 500,
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ok: false,
            error: {
              code: "SIMULATED_TRANSPORT_FAILURE",
              message: "Injected runtime transport failure",
            },
          }),
        };
      }

      if (params && params.__simulate_transport_failure_once === true) {
        const marker =
          typeof params.retry_marker === "string" && params.retry_marker
            ? params.retry_marker
            : typeof requestId === "string" && requestId
            ? requestId
            : `${nodeRuntime.nodeId}:${instance.containerId}:once`;
        if (!failureOnceKeys.has(marker)) {
          failureOnceKeys.add(marker);
          return {
            statusCode: 500,
            headers: {
              "content-type": "application/json",
            },
            body: JSON.stringify({
              ok: false,
              error: {
                code: "SIMULATED_TRANSPORT_FAILURE",
                message: "Injected one-shot runtime transport failure",
              },
            }),
          };
        }
      }

      const runtimeDelayMs = normalizeNonNegativeInt(params && params.__runtime_delay_ms, 0);
      if (runtimeDelayMs > 0) {
        await clock.sleep(runtimeDelayMs);
      }

      const idempotencyMarker =
        typeof params.client_idempotency_key === "string" && params.client_idempotency_key
          ? params.client_idempotency_key
          : "";
      const retryMarker = typeof params.retry_marker === "string" && params.retry_marker ? params.retry_marker : "";

      const runtimeEvent = {
        type: "runtime_execute",
        nodeId: nodeRuntime.nodeId,
        containerId: instance.containerId,
        requestId: typeof requestId === "string" ? requestId : "",
        method: rpcMethod,
        idempotencyMarker,
        retryMarker,
        params: deepClone(params),
        timestamp: clock.now(),
      };
      simulationState.runtimeExecutions.push(runtimeEvent);
      trace(runtimeEvent);

      if (params && params.__simulate_jsonrpc_error === true) {
        return {
          statusCode: 200,
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: requestId,
            error: {
              code: -32000,
              message: "simulated_jsonrpc_error",
            },
          }),
        };
      }

      return {
        statusCode: 200,
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: requestId,
          result: {
            ok: true,
            data: {
              nodeId: nodeRuntime.nodeId,
              containerId: instance.containerId,
              method: rpcMethod,
              requestId,
              params: deepClone(params),
            },
          },
        }),
      };
    };
  }

  return function spawnerFactory() {
    return {
      async initialize() {
        return {
          ok: true,
        };
      },
      async spawnSkill(slug) {
        containerSequence += 1;
        const containerId = `${nodeRuntime.nodeId}-container-${containerSequence}`;
        const runtimeHost = `runtime-${containerId}.sim.local`;
        const token = `runtime-token-${containerId}`;
        const networkAddress = `http://${runtimeHost}/rpc`;
        const instance = {
          slug,
          containerId,
          runtimeHost,
          token,
          networkAddress,
        };
        instances.set(containerId, instance);

        transport.registerRuntimeEndpoint({
          protocol: "http:",
          hostname: runtimeHost,
          port: "80",
          ownerNodeId: nodeRuntime.nodeId,
          handler: createRuntimeHandler(instance),
        });

        return {
          ok: true,
          containerId,
          name: `${slug}-${containerId}`,
          token,
          networkAddress,
        };
      },
      async terminateSkill(containerId) {
        const instance = instances.get(containerId);
        if (!instance) {
          return {
            ok: true,
          };
        }
        transport.unregisterRuntimeEndpoint({
          protocol: "http:",
          hostname: instance.runtimeHost,
          port: "80",
        });
        instances.delete(containerId);
        return {
          ok: true,
        };
      },
    };
  };
}

function createNodeHttpHandler(simulationState, nodeRuntime) {
  return async (request) => {
    const requestSigner = nodeRuntime.requestSigner;
    const signerEnabled = Boolean(requestSigner && requestSigner.enabled);
    const contentType = getBaseContentType(request.headers["content-type"]);
    const providedSignature = typeof request.headers["x-signature"] === "string" ? request.headers["x-signature"] : "";

    if (signerEnabled && request.method === "POST" && contentType === "application/json") {
      const verification = requestSigner.parseAndVerify(request.body || "", providedSignature);
      if (!verification.ok) {
        const statusCode = verification.code === "INVALID_SIGNATURE" ? 401 : 400;
        return writeApiError(statusCode, verification.code, verification.message);
      }
    }

    const req = new MockIncomingRequest({
      method: request.method,
      url: request.path,
      headers: request.headers,
      body: request.body || "",
    });
    const res = new MockServerResponse();

    const handling = nodeRuntime.handlers.handle(req, res);
    req.start();
    await handling;

    const rawBody = res.getBody();
    let response = {
      statusCode: res.statusCode,
      headers: res.getHeaders(),
      body: rawBody,
    };

    if (request.path === "/metrics") {
      response = simulationState.applyMetricsInjection(nodeRuntime, response);
    }

    return response;
  };
}

function extractMetricGauge(gauges, name, matcher = null) {
  if (!Array.isArray(gauges)) {
    return null;
  }
  for (const gauge of gauges) {
    if (!gauge || typeof gauge !== "object") {
      continue;
    }
    if (gauge.name !== name) {
      continue;
    }
    const labels = gauge.labels && typeof gauge.labels === "object" ? gauge.labels : {};
    if (typeof matcher === "function" && matcher(labels) !== true) {
      continue;
    }
    return gauge;
  }
  return null;
}

function upsertGauge(gauges, name, value, labels = {}) {
  const normalizedLabels = labels && typeof labels === "object" ? labels : {};
  let replaced = false;
  for (let index = 0; index < gauges.length; index += 1) {
    const gauge = gauges[index];
    if (!gauge || typeof gauge !== "object") {
      continue;
    }
    if (gauge.name !== name) {
      continue;
    }
    const existingLabels = gauge.labels && typeof gauge.labels === "object" ? gauge.labels : {};
    const sameLabels = hashStable(existingLabels) === hashStable(normalizedLabels);
    if (!sameLabels) {
      continue;
    }
    gauges[index] = {
      ...gauge,
      name,
      value,
      labels: { ...normalizedLabels },
    };
    replaced = true;
    break;
  }
  if (!replaced) {
    gauges.push({
      name,
      value,
      labels: { ...normalizedLabels },
    });
  }
}

function counterValue(snapshot, name, labelMatcher = null) {
  if (!snapshot || !Array.isArray(snapshot.counters)) {
    return 0;
  }
  let sum = 0;
  for (const entry of snapshot.counters) {
    if (!entry || typeof entry !== "object" || entry.name !== name) {
      continue;
    }
    const labels = entry.labels && typeof entry.labels === "object" ? entry.labels : {};
    if (typeof labelMatcher === "function" && labelMatcher(labels) !== true) {
      continue;
    }
    sum += Number.isFinite(Number(entry.value)) ? Number(entry.value) : 0;
  }
  return sum;
}

function gaugeValue(snapshot, name, labelMatcher = null) {
  if (!snapshot || !Array.isArray(snapshot.gauges)) {
    return null;
  }
  for (const entry of snapshot.gauges) {
    if (!entry || typeof entry !== "object" || entry.name !== name) {
      continue;
    }
    const labels = entry.labels && typeof entry.labels === "object" ? entry.labels : {};
    if (typeof labelMatcher === "function" && labelMatcher(labels) !== true) {
      continue;
    }
    const numeric = Number(entry.value);
    if (!Number.isFinite(numeric)) {
      continue;
    }
    return numeric;
  }
  return null;
}

function createClusterSimulator(options = {}) {
  const contextStore = new AsyncLocalStorage();
  const realSetImmediate = typeof global.setImmediate === "function" ? global.setImmediate.bind(global) : null;
  const prng = createDeterministicPrng(options.seed || DEFAULT_RANDOM_SEED);
  const baseDir =
    typeof options.baseDir === "string" && options.baseDir.trim()
      ? path.resolve(options.baseDir.trim())
      : path.resolve(process.cwd(), "data", "simulation-phase-18");

  const validation = {
    no_split_brain_under_partition: false,
    no_duplicate_execution_detected: false,
    freeze_behavior_correct: false,
    rolling_upgrade_invariants_hold: false,
    idempotency_consistent_across_nodes: false,
    snapshot_consistency_preserved: false,
    snapshot_persistence_consistent_after_restart: false,
    no_spurious_leader_change_on_restart: false,
    partition_baseline_consistent_after_restart: false,
    retry_backoff_deterministic: false,
    no_hidden_global_state: false,
    no_deadlock_detected: false,
    mixed_tool_skill_load_stable: false,
    errors: [],
  };

  const state = {
    started: false,
    runCounter: 0,
    requestCounter: 0,
    scenarioCounter: 0,
    nodes: new Map(),
    nodeOrder: [],
    clusterManagers: new Map(),
    runtimeExecutions: [],
    traces: [],
    requestTraceByKey: new Map(),
    currentConfig: null,
    clock: null,
    clockRestore: null,
    transport: null,
    faultInjector: null,
    clusterManagerPatchRestore: null,
    createSupervisorV1: null,
    supervisorModulePath: require.resolve("../supervisor/supervisor-v1.js"),
  };

  function now() {
    return state.clock ? state.clock.now() : Date.now();
  }

  function trace(event) {
    const record = {
      timestamp: now(),
      ...event,
    };
    state.traces.push(record);
  }

  function runWithContext(context, fn) {
    const existing = contextStore.getStore() || {};
    const merged = {
      ...existing,
      ...(context && typeof context === "object" ? context : {}),
    };
    return contextStore.run(merged, fn);
  }

  async function flushMicrotasks(turns = 8) {
    for (let index = 0; index < turns; index += 1) {
      await Promise.resolve();
    }
  }

  async function yieldRealEventLoop() {
    if (!realSetImmediate) {
      return;
    }
    await new Promise((resolve) => {
      realSetImmediate(resolve);
    });
  }

  async function advanceTime(ms) {
    if (!state.clock) {
      throw new Error("clock is not initialized");
    }
    state.clock.advance(ms);
    await flushMicrotasks();
    await yieldRealEventLoop();
    return {
      ok: true,
      now: state.clock.now(),
      advancedMs: ms,
    };
  }

  async function advanceTicks(count = 1) {
    const ticks = normalizePositiveInt(count, 1);
    const tickMs = state.currentConfig ? state.currentConfig.heartbeatIntervalMs : DEFAULT_HEARTBEAT_INTERVAL_MS;
    for (let index = 0; index < ticks; index += 1) {
      await advanceTime(tickMs);
    }
    return {
      ok: true,
      ticks,
      now: state.clock.now(),
    };
  }

  async function awaitWithClock(promise, options = {}) {
    const stepMs = normalizePositiveInt(options.stepMs, 250);
    const maxAdvanceMs = normalizePositiveInt(options.maxAdvanceMs, 60000);
    let settled = false;
    let resolvedValue;
    let rejectedError = null;

    Promise.resolve(promise)
      .then((value) => {
        settled = true;
        resolvedValue = value;
      })
      .catch((error) => {
        settled = true;
        rejectedError = error;
      });

    let elapsed = 0;
    while (!settled && elapsed <= maxAdvanceMs) {
      await advanceTime(stepMs);
      elapsed += stepMs;
    }

    if (!settled) {
      throw new Error("operation did not settle within deterministic clock window");
    }

    if (rejectedError) {
      throw rejectedError;
    }

    return resolvedValue;
  }

  function recordClusterTrace(type, nodeId, payload) {
    const context = contextStore.getStore() || {};
    const requestId = typeof context.requestId === "string" ? context.requestId : "";
    const key = requestId ? `${nodeId}:${requestId}` : "";

    trace({
      type,
      nodeId,
      requestId,
      payload: payload ? deepClone(payload) : {},
    });

    if (!key) {
      return;
    }

    let requestTrace = state.requestTraceByKey.get(key);
    if (!requestTrace) {
      requestTrace = {
        nodeId,
        requestId,
        snapshotStartVersion: null,
        resolveVersions: [],
      };
      state.requestTraceByKey.set(key, requestTrace);
    }

    if (type === "cluster_get_snapshot") {
      const snapshotVersion = Number(payload && payload.snapshotVersion);
      if (Number.isFinite(snapshotVersion) && requestTrace.snapshotStartVersion === null) {
        requestTrace.snapshotStartVersion = snapshotVersion;
      }
    }

    if (type === "cluster_resolve_owner") {
      const snapshotVersion = Number(payload && payload.snapshotVersion);
      if (Number.isFinite(snapshotVersion)) {
        requestTrace.resolveVersions.push(snapshotVersion);
      }
    }
  }

  function installClusterManagerTracingPatch() {
    const clusterManagerModulePath = require.resolve("../cluster/cluster-manager.js");
    const clusterManagerModule = require(clusterManagerModulePath);
    const originalCreateClusterManager = clusterManagerModule.createClusterManager;

    clusterManagerModule.createClusterManager = function createTracedClusterManager(options = {}) {
      const manager = originalCreateClusterManager(options);
      const nodeId = normalizeNodeId(manager.nodeId || options.nodeId);
      if (nodeId) {
        state.clusterManagers.set(nodeId, manager);
      }

      const originalGetSnapshot = manager.getSnapshot.bind(manager);
      manager.getSnapshot = function tracedGetSnapshot(...args) {
        const snapshot = originalGetSnapshot(...args);
        recordClusterTrace("cluster_get_snapshot", nodeId, {
          snapshotVersion: snapshot && Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
          stableSnapshotVersion:
            snapshot && Number.isFinite(Number(snapshot.stableSnapshotVersion))
              ? Number(snapshot.stableSnapshotVersion)
              : snapshot && Number.isFinite(Number(snapshot.version))
              ? Number(snapshot.version)
              : 0,
        });
        return snapshot;
      };

      const originalResolveOwnerForSlug = manager.resolveOwnerForSlug.bind(manager);
      manager.resolveOwnerForSlug = function tracedResolveOwnerForSlug(...args) {
        const result = originalResolveOwnerForSlug(...args);
        recordClusterTrace("cluster_resolve_owner", nodeId, {
          snapshotVersion: result && Number.isFinite(Number(result.snapshotVersion)) ? Number(result.snapshotVersion) : 0,
          ownerNodeId: result && typeof result.ownerNodeId === "string" ? result.ownerNodeId : "",
          shardId: result && Number.isFinite(Number(result.shardId)) ? Number(result.shardId) : null,
        });
        return result;
      };

      return manager;
    };

    delete require.cache[state.supervisorModulePath];
    const supervisorModule = require(state.supervisorModulePath);
    state.createSupervisorV1 = supervisorModule.createSupervisorV1;

    return () => {
      clusterManagerModule.createClusterManager = originalCreateClusterManager;
      delete require.cache[state.supervisorModulePath];
    };
  }

  function buildNodeDefaults(config = {}) {
    const nodeCount = normalizePositiveInt(config.nodeCount, DEFAULT_NODE_COUNT);
    const shardCount = normalizePositiveInt(config.shardCount, DEFAULT_SHARD_COUNT);
    const heartbeatIntervalMs = normalizePositiveInt(config.heartbeatIntervalMs, DEFAULT_HEARTBEAT_INTERVAL_MS);
    const leaderTimeoutMs = normalizePositiveInt(config.leaderTimeoutMs, DEFAULT_LEADER_TIMEOUT_MS);
    const convergenceWindowMs = normalizePositiveInt(config.convergenceWindowMs, DEFAULT_CONVERGENCE_WINDOW_MS);
    const softwareVersion = typeof config.softwareVersion === "string" && config.softwareVersion.trim() ? config.softwareVersion.trim() : DEFAULT_SOFTWARE_VERSION;
    const queueMaxLength = normalizePositiveInt(config.queueMaxLength, 128);
    const queuePollIntervalMs = normalizePositiveInt(config.queuePollIntervalMs, DEFAULT_QUEUE_POLL_INTERVAL_MS);
    const requestTimeoutMs = normalizePositiveInt(config.requestTimeoutMs, 30000);

    return {
      nodeCount,
      shardCount,
      heartbeatIntervalMs,
      leaderTimeoutMs,
      convergenceWindowMs,
      softwareVersion,
      queueMaxLength,
      queuePollIntervalMs,
      requestTimeoutMs,
    };
  }

  function buildNodeConfig(globalConfig, index, explicitNode) {
    const fallbackNodeId = `node-${index + 1}`;
    const nodeId = normalizeNodeId(explicitNode && explicitNode.nodeId ? explicitNode.nodeId : fallbackNodeId) || fallbackNodeId;
    const softwareVersion =
      typeof (explicitNode && explicitNode.softwareVersion) === "string" && explicitNode.softwareVersion.trim()
        ? explicitNode.softwareVersion.trim()
        : globalConfig.softwareVersion;
    const host = `sim-${nodeId}.cluster.local`;
    const baseUrl = `http://${host}`;
    const authToken = typeof (explicitNode && explicitNode.authToken) === "string" && explicitNode.authToken.trim()
      ? explicitNode.authToken.trim()
      : `auth-token-${nodeId}`;
    const requestSigningEnabled = normalizeBoolean(explicitNode && explicitNode.requestSigningEnabled, false);
    const requestSigningSecret =
      typeof (explicitNode && explicitNode.requestSigningSecret) === "string" && explicitNode.requestSigningSecret.trim()
        ? explicitNode.requestSigningSecret.trim()
        : `signing-secret-${nodeId}`;

    return {
      nodeId,
      softwareVersion,
      baseUrl,
      host,
      authToken,
      requestSigningEnabled,
      requestSigningSecret,
    };
  }

  function getNodeRuntime(rawNodeId) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return null;
    }
    return state.nodes.get(nodeId) || null;
  }

  function listNodeIds() {
    return state.nodeOrder.slice();
  }

  function requestId(prefix = "req") {
    state.requestCounter += 1;
    return `${prefix}-${state.runCounter}-${state.requestCounter}`;
  }

  async function callNodeRequest(nodeRuntime, request) {
    const targetNodeId = nodeRuntime.nodeId;
    const headers = normalizeHeaders(request.headers);
    const authHeader = typeof headers.authorization === "string" ? headers.authorization : "";
    const requestIdHeader = typeof headers["x-request-id"] === "string" ? headers["x-request-id"] : "";

    trace({
      type: "external_request",
      nodeId: targetNodeId,
      path: request.path,
      method: request.method,
      requestId: requestIdHeader,
      authPresent: Boolean(authHeader),
    });

    return runWithContext(
      {
        nodeId: targetNodeId,
        requestId: requestIdHeader,
      },
      async () => {
        const response = await nodeRuntime.httpHandler({
          method: request.method,
          path: request.path,
          headers,
          body: request.body || "",
          sourceNodeId: normalizeNodeId(request.sourceNodeId),
          targetNodeId,
        });
        return response;
      },
    );
  }

  async function sendJsonRequest(rawNodeId, request = {}) {
    const nodeRuntime = getNodeRuntime(rawNodeId);
    if (!nodeRuntime) {
      throw new Error(`node '${rawNodeId}' not found`);
    }

    const method = typeof request.method === "string" && request.method ? request.method.toUpperCase() : "POST";
    const pathName = typeof request.path === "string" && request.path ? request.path : "/api/v1/execute";
    const bodyObject = request.bodyObject && typeof request.bodyObject === "object" ? request.bodyObject : {};
    const body = typeof request.body === "string" ? request.body : JSON.stringify(bodyObject);
    const requestIdValue = typeof request.requestId === "string" && request.requestId ? request.requestId : requestId("http");
    const principalId = typeof request.principalId === "string" && request.principalId ? request.principalId : "sim-principal";
    const authToken = typeof request.authToken === "string" && request.authToken ? request.authToken : nodeRuntime.authToken;
    const signRequest = request.sign !== false;

    const headers = normalizeHeaders({
      "content-type": "application/json",
      authorization: authToken ? `Bearer ${authToken}` : "",
      "x-request-id": requestIdValue,
      "x-principal-id": principalId,
      ...(request.headers || {}),
    });

    if (signRequest && nodeRuntime.requestSigner && nodeRuntime.requestSigner.enabled) {
      let parsed;
      try {
        parsed = body ? JSON.parse(body) : {};
      } catch {
        parsed = {};
      }
      headers["x-signature"] = nodeRuntime.requestSigner.signPayload(parsed);
    }

    const response = await callNodeRequest(nodeRuntime, {
      method,
      path: pathName,
      headers,
      body,
      sourceNodeId: request.sourceNodeId || "external-client",
    });

    let parsedBody = null;
    try {
      parsedBody = response && response.body ? JSON.parse(response.body) : null;
    } catch {
      parsedBody = null;
    }

    return {
      statusCode: response.statusCode,
      headers: normalizeHeaders(response.headers),
      body: response.body || "",
      json: parsedBody,
      requestId: requestIdValue,
    };
  }

  async function sendJsonRequestSettled(rawNodeId, request = {}, waitOptions = {}) {
    const settled = await waitForSettled([sendJsonRequest(rawNodeId, request)], {
      stepMs: normalizePositiveInt(waitOptions.stepMs, 250),
      maxAdvanceMs: normalizePositiveInt(waitOptions.maxAdvanceMs, 15000),
    });

    if (!settled.ok || settled.timeout || !Array.isArray(settled.results) || settled.results.length === 0) {
      throw new Error("request did not settle within deterministic clock window");
    }

    const first = settled.results[0];
    if (!first || first.status !== "fulfilled") {
      const reason = first && Object.prototype.hasOwnProperty.call(first, "reason") ? first.reason : null;
      if (reason instanceof Error) {
        throw reason;
      }
      throw new Error("request failed");
    }

    return first.value;
  }

  function clusterSnapshot(rawNodeId) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return null;
    }
    const manager = state.clusterManagers.get(nodeId);
    if (!manager || typeof manager.getSnapshot !== "function") {
      return null;
    }
    return manager.getSnapshot();
  }

  function snapshotDigest(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return "";
    }
    return hashStable({
      version: snapshot.version,
      stableSnapshotVersion: snapshot.stableSnapshotVersion,
      healthyNodes: Array.isArray(snapshot.healthyNodes)
        ? snapshot.healthyNodes.map((item) => ({
            nodeId: item.nodeId,
            isLocal: item.isLocal,
          }))
        : [],
      partition: snapshot.partition || null,
      leader: snapshot.leader || null,
      convergence: snapshot.convergence || null,
    });
  }

  function metricsSnapshot(rawNodeId) {
    const runtime = getNodeRuntime(rawNodeId);
    if (!runtime) {
      return null;
    }
    return runtime.supervisor.getMetrics();
  }

  async function initializeNodeRuntime(nodeRuntime) {
    await awaitWithClock(
      runWithContext({ nodeId: nodeRuntime.nodeId }, async () => {
        await nodeRuntime.supervisor.initialize();
      }),
      {
        maxAdvanceMs: 120000,
      },
    );
  }

  async function shutdownNodeRuntime(nodeRuntime) {
    await awaitWithClock(
      runWithContext({ nodeId: nodeRuntime.nodeId }, async () => {
        await nodeRuntime.supervisor.shutdown();
      }),
      {
        maxAdvanceMs: 120000,
      },
    );
  }

  async function createNodeRuntime(nodeConfig, globalConfig) {
    const metrics = createMetrics();
    const peerRegistry = createPeerRegistry();
    const statePath = path.resolve(baseDir, `state-${nodeConfig.nodeId}.json`);
    const configHash = hashStable({
      shardCount: globalConfig.shardCount,
      heartbeatIntervalMs: globalConfig.heartbeatIntervalMs,
      leaderTimeoutMs: globalConfig.leaderTimeoutMs,
      convergenceWindowMs: globalConfig.convergenceWindowMs,
    });
    const requestSigner = createRequestSigner({
      enabled: nodeConfig.requestSigningEnabled,
      secret: nodeConfig.requestSigningSecret,
    });

    const runtime = {
      nodeId: nodeConfig.nodeId,
      softwareVersion: nodeConfig.softwareVersion,
      authToken: nodeConfig.authToken,
      host: nodeConfig.host,
      baseUrl: nodeConfig.baseUrl,
      protocol: "http:",
      port: "80",
      metrics,
      peerRegistry,
      statePath,
      configHash,
      requestSigner,
      requestSigningEnabled: nodeConfig.requestSigningEnabled,
      requestSigningSecret: nodeConfig.requestSigningSecret,
      supervisor: null,
      handlers: null,
      httpHandler: null,
    };

    const spawnerFactory = createFakeSpawnerFactory(state, runtime);
    const toolAdapter = createSimulationToolAdapter(runtime.nodeId, state.clock, trace);

    runtime.supervisor = state.createSupervisorV1({
      requestTimeoutMs: globalConfig.requestTimeoutMs,
      spawnerFactory,
      auth: {
        enabled: true,
        mode: "bearer",
        bearerToken: runtime.authToken,
      },
      rateLimit: {
        enabled: false,
      },
      idempotency: {
        enabled: true,
        ttlMs: 300000,
        maxEntries: 10000,
      },
      queue: {
        enabled: true,
        maxLength: globalConfig.queueMaxLength,
        pollIntervalMs: globalConfig.queuePollIntervalMs,
      },
      state: {
        enabled: true,
        path: statePath,
        debounceMs: 1000,
        queueItemTtlMs: 300000,
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 15000,
      },
      federation: {
        enabled: true,
        peerRegistry,
        timeoutMs: 30000,
        heartbeatIntervalMs: 60000,
        heartbeatTimeoutMs: 5000,
      },
      cluster: {
        enabled: true,
        nodeId: runtime.nodeId,
        shardCount: globalConfig.shardCount,
        heartbeatIntervalMs: globalConfig.heartbeatIntervalMs,
        leaderTimeoutMs: globalConfig.leaderTimeoutMs,
        convergenceWindowMs: globalConfig.convergenceWindowMs,
      },
      deployment: {
        softwareVersion: runtime.softwareVersion,
        configHash: runtime.configHash,
        // Simulator uses in-memory handler dispatch, so HTTP listener bootstrap is not enabled.
        httpEnabled: false,
        tls: {
          enabled: false,
        },
      },
      metrics,
      toolAdapters: {
        "sim-tool": toolAdapter,
      },
    });

    runtime.handlers = createHttpHandlers({
      supervisor: runtime.supervisor,
      metrics,
      authEnabled: true,
      isShuttingDown: () => false,
    });
    runtime.httpHandler = createNodeHttpHandler(state, runtime);

    return runtime;
  }

  function connectPeerRegistries(targetStatus = STATUS_UP) {
    for (const sourceNodeId of state.nodeOrder) {
      const sourceNode = state.nodes.get(sourceNodeId);
      if (!sourceNode) {
        continue;
      }
      for (const targetNodeId of state.nodeOrder) {
        if (targetNodeId === sourceNodeId) {
          continue;
        }
        const targetNode = state.nodes.get(targetNodeId);
        if (!targetNode) {
          continue;
        }
        const existing = sourceNode.peerRegistry.getPeer(targetNode.nodeId);
        if (existing) {
          sourceNode.peerRegistry.updatePeerHealth(targetNode.nodeId, {
            status: targetStatus === STATUS_UP ? STATUS_UP : STATUS_DOWN,
            lastHeartbeat: now(),
            capabilities: ["nmap", "sim-tool"],
          });
          continue;
        }
        sourceNode.peerRegistry.registerPeer(targetNode.nodeId, {
          url: targetNode.baseUrl,
          authToken: targetNode.authToken,
          status: targetStatus === STATUS_UP ? STATUS_UP : STATUS_DOWN,
          capabilities: ["nmap", "sim-tool"],
          lastHeartbeat: now(),
          lastLatencyMs: 0,
        });
      }
    }
  }

  function connectNodeToInitializedPeers(nodeId, initializedNodeIds = []) {
    const runtime = state.nodes.get(nodeId);
    if (!runtime) {
      return;
    }
    for (const peerId of initializedNodeIds) {
      if (!peerId || peerId === nodeId) {
        continue;
      }
      const peerRuntime = state.nodes.get(peerId);
      if (!peerRuntime) {
        continue;
      }

      const existingInCurrent = runtime.peerRegistry.getPeer(peerRuntime.nodeId);
      if (existingInCurrent) {
        runtime.peerRegistry.updatePeerHealth(peerRuntime.nodeId, {
          status: STATUS_UP,
          lastHeartbeat: now(),
          capabilities: ["nmap", "sim-tool"],
        });
      } else {
        runtime.peerRegistry.registerPeer(peerRuntime.nodeId, {
          url: peerRuntime.baseUrl,
          authToken: peerRuntime.authToken,
          status: STATUS_UP,
          capabilities: ["nmap", "sim-tool"],
          lastHeartbeat: now(),
          lastLatencyMs: 0,
        });
      }

      const existingInPeer = peerRuntime.peerRegistry.getPeer(runtime.nodeId);
      if (existingInPeer) {
        peerRuntime.peerRegistry.updatePeerHealth(runtime.nodeId, {
          status: STATUS_DOWN,
          lastHeartbeat: now(),
          capabilities: ["nmap", "sim-tool"],
        });
      } else {
        peerRuntime.peerRegistry.registerPeer(runtime.nodeId, {
          url: runtime.baseUrl,
          authToken: runtime.authToken,
          status: STATUS_DOWN,
          capabilities: ["nmap", "sim-tool"],
          lastHeartbeat: now(),
          lastLatencyMs: 0,
        });
      }
    }
  }

  function registerTransportEndpoints() {
    for (const nodeId of state.nodeOrder) {
      const nodeRuntime = state.nodes.get(nodeId);
      if (!nodeRuntime) {
        continue;
      }
      state.transport.registerNodeEndpoint({
        protocol: nodeRuntime.protocol,
        hostname: nodeRuntime.host,
        port: nodeRuntime.port,
        nodeId: nodeRuntime.nodeId,
        requestSigner: nodeRuntime.requestSigner,
        allowAutoSign: true,
        softwareVersion: nodeRuntime.softwareVersion,
        configHash: nodeRuntime.configHash,
        handler: nodeRuntime.httpHandler,
      });
    }
  }

  function unregisterTransportEndpoints() {
    if (!state.transport) {
      return;
    }
    for (const nodeId of state.nodeOrder) {
      const nodeRuntime = state.nodes.get(nodeId);
      if (!nodeRuntime) {
        continue;
      }
      state.transport.unregisterNodeEndpoint({
        protocol: nodeRuntime.protocol,
        hostname: nodeRuntime.host,
        port: nodeRuntime.port,
      });
    }
  }

  function applyMetricsInjection(nodeRuntime, response) {
    const versionOverride = state.faultInjector.getInjectedVersion(nodeRuntime.nodeId);
    const configPatch = state.faultInjector.getInjectedConfig(nodeRuntime.nodeId);
    if (!versionOverride && !configPatch) {
      return response;
    }

    let payload;
    try {
      payload = response && response.body ? JSON.parse(response.body) : null;
    } catch {
      return response;
    }
    if (!payload || !payload.metrics || !Array.isArray(payload.metrics.gauges)) {
      return response;
    }

    const gauges = payload.metrics.gauges.slice();
    const metadataGauge = extractMetricGauge(gauges, "cluster.node_metadata", (labels) => labels.node_id === nodeRuntime.nodeId);
    if (metadataGauge) {
      metadataGauge.labels = {
        ...(metadataGauge.labels || {}),
        node_id: nodeRuntime.nodeId,
        software_version: versionOverride || metadataGauge.labels.software_version || nodeRuntime.softwareVersion,
        config_hash: (configPatch && configPatch.configHash) || metadataGauge.labels.config_hash || nodeRuntime.configHash,
      };
    } else {
      gauges.push({
        name: "cluster.node_metadata",
        value: 1,
        labels: {
          node_id: nodeRuntime.nodeId,
          software_version: versionOverride || nodeRuntime.softwareVersion,
          config_hash: (configPatch && configPatch.configHash) || nodeRuntime.configHash,
        },
      });
    }

    if (configPatch) {
      if (Number.isFinite(Number(configPatch.shardCount))) {
        upsertGauge(gauges, "cluster.shard_count", Number(configPatch.shardCount), {});
      }
      if (Number.isFinite(Number(configPatch.leaderTimeoutMs))) {
        upsertGauge(gauges, "cluster.leader_timeout_ms", Number(configPatch.leaderTimeoutMs), {});
      }
      if (Number.isFinite(Number(configPatch.heartbeatIntervalMs))) {
        upsertGauge(gauges, "cluster.heartbeat_interval_ms", Number(configPatch.heartbeatIntervalMs), {});
      }
    }

    payload.metrics.gauges = gauges;
    return {
      statusCode: response.statusCode,
      headers: response.headers,
      body: JSON.stringify(payload),
    };
  }

  state.applyMetricsInjection = applyMetricsInjection;
  state.trace = trace;

  async function ensureBaseDir() {
    await fs.mkdir(baseDir, { recursive: true });
  }

  async function startCluster(config = {}) {
    if (state.started) {
      return {
        ok: true,
        started: false,
        nodeCount: state.nodeOrder.length,
      };
    }

    state.runCounter += 1;
    state.requestCounter = 0;
    state.scenarioCounter = 0;
    state.runtimeExecutions = [];
    state.traces = [];
    state.requestTraceByKey.clear();
    state.clusterManagers.clear();
    state.nodes.clear();
    state.nodeOrder = [];
    await ensureBaseDir();

    const defaults = buildNodeDefaults(config);
    state.currentConfig = {
      ...defaults,
    };

    state.clock = createDeterministicClock({
      startMs: normalizeNonNegativeInt(config.clockStartMs, DEFAULT_CLOCK_START_MS),
      contextStore,
      runWithContext,
    });
    state.clockRestore = installDeterministicTimeEnvironment(state.clock);
    state.faultInjector = createFaultInjector({
      defaultLatencyMs: normalizeNonNegativeInt(config.defaultLatencyMs, 0),
    });

    state.transport = createInMemoryTransport({
      contextStore,
      runWithContext,
      clock: state.clock,
      faultInjector: state.faultInjector,
      trace,
    });
    state.transport.installPatches();

    state.clusterManagerPatchRestore = installClusterManagerTracingPatch();

    const explicitNodes = Array.isArray(config.nodes) ? config.nodes : [];
    const nodeCount = explicitNodes.length > 0 ? explicitNodes.length : defaults.nodeCount;

    for (let index = 0; index < nodeCount; index += 1) {
      const explicitNode = explicitNodes[index] || null;
      const nodeConfig = buildNodeConfig(defaults, index, explicitNode);
      const nodeRuntime = await createNodeRuntime(nodeConfig, defaults);
      state.nodes.set(nodeRuntime.nodeId, nodeRuntime);
      state.nodeOrder.push(nodeRuntime.nodeId);
    }

    registerTransportEndpoints();

    const initializedNodeIds = [];
    for (const nodeId of state.nodeOrder) {
      const runtime = state.nodes.get(nodeId);
      connectNodeToInitializedPeers(nodeId, initializedNodeIds);
      await initializeNodeRuntime(runtime);
      initializedNodeIds.push(nodeId);
    }

    connectPeerRegistries(STATUS_UP);
    await advanceTicks(3);
    state.started = true;

    validation.no_hidden_global_state = validateIsolationInvariants();

    return {
      ok: true,
      started: true,
      nodeCount: state.nodeOrder.length,
      nodeIds: state.nodeOrder.slice(),
      now: now(),
    };
  }

  async function stopCluster() {
    if (!state.started) {
      return {
        ok: true,
        stopped: false,
      };
    }

    for (const nodeId of state.nodeOrder.slice()) {
      const runtime = state.nodes.get(nodeId);
      if (!runtime) {
        continue;
      }
      try {
        await shutdownNodeRuntime(runtime);
      } catch {}
    }

    unregisterTransportEndpoints();
    if (state.transport) {
      state.transport.restorePatches();
    }

    if (typeof state.clusterManagerPatchRestore === "function") {
      state.clusterManagerPatchRestore();
    }
    if (typeof state.clockRestore === "function") {
      state.clockRestore();
    }

    state.started = false;
    state.currentConfig = null;
    state.clusterManagers.clear();
    state.nodes.clear();
    state.nodeOrder = [];
    state.transport = null;
    state.faultInjector = null;
    state.clock = null;
    state.clockRestore = null;
    state.clusterManagerPatchRestore = null;
    state.createSupervisorV1 = null;

    return {
      ok: true,
      stopped: true,
    };
  }

  function assertStarted() {
    if (!state.started) {
      throw new Error("cluster is not started");
    }
  }

  async function injectPartition(nodesA = [], nodesB = []) {
    assertStarted();
    const result = state.faultInjector.setPartition(nodesA, nodesB);
    await advanceTicks(2);
    return {
      ok: true,
      result,
    };
  }

  async function resolvePartition() {
    assertStarted();
    state.faultInjector.clearPartition();
    await advanceTicks(2);
    return {
      ok: true,
    };
  }

  async function replaceNodeRuntime(nodeId, replacement) {
    const existing = getNodeRuntime(nodeId);
    if (!existing) {
      throw new Error(`node '${nodeId}' not found`);
    }

    await shutdownNodeRuntime(existing);
    state.transport.unregisterNodeEndpoint({
      protocol: existing.protocol,
      hostname: existing.host,
      port: existing.port,
    });

    const nodeConfig = {
      nodeId: existing.nodeId,
      softwareVersion: replacement.softwareVersion || existing.softwareVersion,
      host: existing.host,
      baseUrl: existing.baseUrl,
      authToken: replacement.authToken || existing.authToken,
      requestSigningEnabled:
        typeof replacement.requestSigningEnabled === "boolean"
          ? replacement.requestSigningEnabled
          : existing.requestSigningEnabled,
      requestSigningSecret: replacement.requestSigningSecret || existing.requestSigningSecret,
    };

    const globalConfig = state.currentConfig || buildNodeDefaults({});
    const rebuilt = await createNodeRuntime(nodeConfig, globalConfig);
    rebuilt.statePath = existing.statePath;
    state.nodes.set(nodeId, rebuilt);
    state.transport.registerNodeEndpoint({
      protocol: rebuilt.protocol,
      hostname: rebuilt.host,
      port: rebuilt.port,
      nodeId: rebuilt.nodeId,
      requestSigner: rebuilt.requestSigner,
      allowAutoSign: true,
      softwareVersion: rebuilt.softwareVersion,
      configHash: rebuilt.configHash,
      handler: rebuilt.httpHandler,
    });
    connectPeerRegistries();
    await initializeNodeRuntime(rebuilt);
    await advanceTicks(2);
    return rebuilt;
  }

  async function restartNode(rawNodeId, restartOptions = {}) {
    assertStarted();
    const nodeId = normalizeNodeId(rawNodeId);
    const runtime = getNodeRuntime(nodeId);
    if (!runtime) {
      throw new Error(`node '${nodeId}' not found`);
    }

    const beforeSnapshot = clusterSnapshot(nodeId);
    const beforeDigest = snapshotDigest(beforeSnapshot);

    const replacement = await replaceNodeRuntime(nodeId, {
      softwareVersion:
        typeof restartOptions.softwareVersion === "string" && restartOptions.softwareVersion.trim()
          ? restartOptions.softwareVersion.trim()
          : runtime.softwareVersion,
      authToken:
        typeof restartOptions.authToken === "string" && restartOptions.authToken.trim()
          ? restartOptions.authToken.trim()
          : runtime.authToken,
      requestSigningEnabled:
        typeof restartOptions.requestSigningEnabled === "boolean"
          ? restartOptions.requestSigningEnabled
          : runtime.requestSigningEnabled,
      requestSigningSecret:
        typeof restartOptions.requestSigningSecret === "string" && restartOptions.requestSigningSecret.trim()
          ? restartOptions.requestSigningSecret.trim()
          : runtime.requestSigningSecret,
    });

    const afterSnapshot = clusterSnapshot(nodeId);
    const afterDigest = snapshotDigest(afterSnapshot);

    trace({
      type: "node_restart",
      nodeId,
      beforeDigest,
      afterDigest,
      softwareVersionBefore: runtime.softwareVersion,
      softwareVersionAfter: replacement.softwareVersion,
    });

    return {
      ok: true,
      nodeId,
      beforeSnapshot,
      afterSnapshot,
      beforeDigest,
      afterDigest,
    };
  }

  async function simulateRollingUpgrade(rawNodeId, newVersion) {
    assertStarted();
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      throw new Error("nodeId is required");
    }
    const softwareVersion = typeof newVersion === "string" && newVersion.trim() ? newVersion.trim() : "";
    if (!softwareVersion) {
      throw new Error("newVersion is required");
    }
    const result = await restartNode(nodeId, {
      softwareVersion,
    });
    await advanceTicks(2);
    return {
      ok: true,
      nodeId,
      softwareVersion,
      restart: result,
    };
  }

  async function waitForSettled(promises, options = {}) {
    const stepMs = normalizePositiveInt(options.stepMs, 250);
    const maxAdvanceMs = normalizePositiveInt(options.maxAdvanceMs, 30000);
    const wrapped = promises.map((promise) =>
      Promise.resolve(promise)
        .then((value) => ({ status: "fulfilled", value }))
        .catch((reason) => ({ status: "rejected", reason })),
    );
    let done = false;
    let results = null;
    const completion = Promise.all(wrapped).then((resolved) => {
      done = true;
      results = resolved;
      return resolved;
    });

    let elapsed = 0;
    while (!done && elapsed <= maxAdvanceMs) {
      await advanceTime(stepMs);
      elapsed += stepMs;
    }

    if (!done) {
      return {
        ok: false,
        timeout: true,
        elapsedMs: elapsed,
        results: [],
      };
    }

    await completion;
    return {
      ok: true,
      timeout: false,
      elapsedMs: elapsed,
      results: results || [],
    };
  }

  async function runMixedLoadScenario(options = {}) {
    assertStarted();
    const totalRequests = normalizePositiveInt(options.totalRequests, 40);
    const nodeIds = listNodeIds();
    const promises = [];

    for (let index = 0; index < totalRequests; index += 1) {
      const ingressNodeId = pickRandom(prng, nodeIds) || nodeIds[index % nodeIds.length];
      const useToolPath = index % 2 === 1;
      const idempotency = `idem-mixed-${Math.floor(index / 4)}`;
      if (useToolPath) {
        promises.push(
          sendJsonRequest(ingressNodeId, {
            method: "POST",
            path: "/api/v1/execute",
            principalId: `principal-${index % 5}`,
            bodyObject: {
              slug: "sim-tool",
              method: "run",
              params: {
                sequence: index,
                delayMs: index % 3 === 0 ? 10 : 0,
              },
            },
          }),
        );
      } else {
        promises.push(
          sendJsonRequest(ingressNodeId, {
            method: "POST",
            path: "/api/v1/execute",
            principalId: `principal-${index % 5}`,
            bodyObject: {
              slug: "nmap",
              method: "run",
              params: {
                target: `host-${index % 11}.example`,
                sequence: index,
                client_idempotency_key: idempotency,
                __runtime_delay_ms: index % 4 === 0 ? 30 : 0,
              },
              idempotencyKey: idempotency,
              retryPolicy: {
                retries: 1,
                delayMs: 1000,
                backoffFactor: 2,
              },
            },
          }),
        );
      }
    }

    const settled = await waitForSettled(promises, {
      stepMs: 250,
      maxAdvanceMs: 45000,
    });

    const fulfilled = settled.results.filter((result) => result.status === "fulfilled");
    const rejected = settled.results.filter((result) => result.status === "rejected");
    const successes = fulfilled.filter((result) => result.value && result.value.statusCode === 200);
    const failureRate = totalRequests > 0 ? (totalRequests - successes.length) / totalRequests : 1;
    const stable = settled.ok && !settled.timeout && rejected.length === 0 && failureRate <= 0.25;

    trace({
      type: "scenario_mixed_load",
      totalRequests,
      succeeded: successes.length,
      rejected: rejected.length,
      timeout: settled.timeout,
    });

    return {
      ok: stable,
      settled: settled.ok,
      timeout: settled.timeout,
      totalRequests,
      succeeded: successes.length,
      failed: totalRequests - successes.length,
      rejectedCount: rejected.length,
      deadlock: settled.timeout,
    };
  }

  async function runAuthSigningScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length === 0) {
      return {
        ok: false,
      };
    }

    const nodeId = nodeIds[0];
    const bodyObject = {
      slug: "sim-tool",
      method: "run",
      params: {
        scenario: "auth-signing",
      },
    };

    const missingAuth = await sendJsonRequestSettled(nodeId, {
      method: "POST",
      path: "/api/v1/execute",
      authToken: "",
      headers: {
        authorization: "",
      },
      sign: false,
      bodyObject,
    });

    const invalidAuth = await sendJsonRequestSettled(nodeId, {
      method: "POST",
      path: "/api/v1/execute",
      authToken: "invalid-token",
      sign: false,
      bodyObject,
    });

    await restartNode(nodeId, {
      requestSigningEnabled: true,
    });

    const validSigned = await sendJsonRequestSettled(nodeId, {
      method: "POST",
      path: "/api/v1/execute",
      bodyObject,
      sign: true,
    });

    const missingSignature = await sendJsonRequestSettled(nodeId, {
      method: "POST",
      path: "/api/v1/execute",
      bodyObject,
      sign: false,
    });

    const invalidSignature = await sendJsonRequestSettled(nodeId, {
      method: "POST",
      path: "/api/v1/execute",
      bodyObject,
      sign: false,
      headers: {
        "x-signature": "invalid-signature",
      },
    });

    await restartNode(nodeId, {
      requestSigningEnabled: false,
    });

    const ok =
      missingAuth.statusCode === 401 &&
      invalidAuth.statusCode === 401 &&
      validSigned.statusCode === 200 &&
      missingSignature.statusCode === 401 &&
      invalidSignature.statusCode === 401;

    return {
      ok,
      missingAuthStatus: missingAuth.statusCode,
      invalidAuthStatus: invalidAuth.statusCode,
      validSignedStatus: validSigned.statusCode,
      missingSignatureStatus: missingSignature.statusCode,
      invalidSignatureStatus: invalidSignature.statusCode,
    };
  }

  function validateSnapshotConsistency() {
    const errors = [];
    for (const [traceKey, requestTrace] of state.requestTraceByKey.entries()) {
      if (!requestTrace || !Array.isArray(requestTrace.resolveVersions) || requestTrace.resolveVersions.length === 0) {
        continue;
      }
      if (!Number.isFinite(Number(requestTrace.snapshotStartVersion))) {
        errors.push({
          invariant: "snapshot_consistency_preserved",
          message: `missing snapshot start version for ${traceKey}`,
        });
        continue;
      }
      const startVersion = Number(requestTrace.snapshotStartVersion);
      for (const version of requestTrace.resolveVersions) {
        if (!Number.isFinite(Number(version)) || Number(version) !== startVersion) {
          errors.push({
            invariant: "snapshot_consistency_preserved",
            message: `snapshot drift for ${traceKey}: expected ${startVersion}, got ${version}`,
          });
          break;
        }
      }
    }
    return {
      ok: errors.length === 0,
      errors,
    };
  }

  async function runIdempotencyScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length < 2) {
      return {
        ok: false,
        noDuplicateExecution: false,
        samePayload: false,
        errors: [
          {
            invariant: "idempotency_consistent_across_nodes",
            message: "requires at least 2 nodes",
          },
        ],
      };
    }

    const ingressA = nodeIds[0];
    const ingressB = nodeIds[1];
    const idempotencyKey = `idem-cross-node-${requestId("idem")}`;
    const payload = {
      slug: "nmap",
      method: "run",
      params: {
        target: "idempotency-scenario.local",
        client_idempotency_key: idempotencyKey,
      },
      idempotencyKey,
      retryPolicy: {
        retries: 1,
        delayMs: 1000,
        backoffFactor: 2,
      },
    };

    const first = await sendJsonRequestSettled(ingressA, {
      method: "POST",
      path: "/api/v1/execute",
      principalId: "idem-principal",
      bodyObject: payload,
    });
    const second = await sendJsonRequestSettled(ingressB, {
      method: "POST",
      path: "/api/v1/execute",
      principalId: "idem-principal",
      bodyObject: payload,
    });

    const firstResult = first && first.json && first.json.data ? first.json.data.result : null;
    const secondResult = second && second.json && second.json.data ? second.json.data.result : null;
    const samePayload = hashStable(firstResult) === hashStable(secondResult);

    const executions = state.runtimeExecutions.filter((entry) => entry && entry.idempotencyMarker === idempotencyKey);
    const noDuplicateExecution = executions.length <= 1;

    return {
      ok: first.statusCode === 200 && second.statusCode === 200 && samePayload && noDuplicateExecution,
      samePayload,
      noDuplicateExecution,
      firstStatusCode: first.statusCode,
      secondStatusCode: second.statusCode,
      executionCount: executions.length,
    };
  }

  async function runEqualSplitScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length < 6) {
      return {
        ok: false,
        noSplitBrain: false,
        partitionedNodeCount: 0,
      };
    }

    const sideA = nodeIds.slice(0, 3);
    const sideB = nodeIds.slice(3, 6);
    const beforeVersions = {};
    for (const nodeId of nodeIds) {
      const snapshot = clusterSnapshot(nodeId);
      beforeVersions[nodeId] = snapshot && Number.isFinite(Number(snapshot.stableSnapshotVersion)) ? Number(snapshot.stableSnapshotVersion) : 0;
    }

    await injectPartition(sideA, sideB);
    await advanceTicks(3);

    let partitionedNodeCount = 0;
    let suppressedLeadership = 0;
    let stableVersionsUnchanged = 0;

    for (const nodeId of nodeIds) {
      const snapshot = clusterSnapshot(nodeId);
      if (snapshot && snapshot.partition && snapshot.partition.partitioned === true) {
        partitionedNodeCount += 1;
      }
      if (snapshot && snapshot.leader && snapshot.leader.transitionsSuppressed === true) {
        suppressedLeadership += 1;
      }
      const currentVersion =
        snapshot && Number.isFinite(Number(snapshot.stableSnapshotVersion))
          ? Number(snapshot.stableSnapshotVersion)
          : snapshot && Number.isFinite(Number(snapshot.version))
          ? Number(snapshot.version)
          : 0;
      if (currentVersion === beforeVersions[nodeId]) {
        stableVersionsUnchanged += 1;
      }
    }

    await resolvePartition();
    await advanceTicks(3);

    const noSplitBrain = partitionedNodeCount === nodeIds.length && suppressedLeadership === nodeIds.length && stableVersionsUnchanged === nodeIds.length;
    return {
      ok: noSplitBrain,
      noSplitBrain,
      partitionedNodeCount,
      suppressedLeadership,
      stableVersionsUnchanged,
    };
  }

  async function runAsymmetricPartitionScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length < 2) {
      return {
        ok: false,
      };
    }

    const fromNodeId = nodeIds[0];
    const toNodeId = nodeIds[1];
    state.faultInjector.setDirectionalDrop(fromNodeId, toNodeId, true);
    await advanceTicks(3);

    const fromSnapshot = clusterSnapshot(fromNodeId);
    const toSnapshot = clusterSnapshot(toNodeId);
    const fromNodeView = fromSnapshot && Array.isArray(fromSnapshot.nodes)
      ? fromSnapshot.nodes.find((node) => node && node.nodeId === toNodeId)
      : null;
    const toNodeView = toSnapshot && Array.isArray(toSnapshot.nodes)
      ? toSnapshot.nodes.find((node) => node && node.nodeId === fromNodeId)
      : null;

    const oneWayObserved = Boolean(
      fromNodeView &&
        toNodeView &&
        fromNodeView.healthy === false &&
        toNodeView.healthy === true,
    );

    state.faultInjector.setDirectionalDrop(fromNodeId, toNodeId, false);
    await advanceTicks(3);

    return {
      ok: oneWayObserved,
      fromNodeId,
      toNodeId,
      oneWayObserved,
    };
  }

  async function runRestartPersistenceScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length < 2) {
      return {
        ok: false,
        snapshotConsistent: false,
        partitionBaselineConsistent: false,
        noSpuriousLeaderChange: false,
      };
    }

    const leaderNode = nodeIds[0];
    const restartNodeId = nodeIds[1];

    const beforeLeaderSnapshot = clusterSnapshot(leaderNode);
    const leaderBefore = beforeLeaderSnapshot && beforeLeaderSnapshot.leader ? beforeLeaderSnapshot.leader.current : null;

    const restartNormal = await restartNode(restartNodeId, {});
    await advanceTicks(2);
    const afterLeaderSnapshot = clusterSnapshot(leaderNode);
    const leaderAfter = afterLeaderSnapshot && afterLeaderSnapshot.leader ? afterLeaderSnapshot.leader.current : null;
    const noSpuriousLeaderChange = leaderBefore === leaderAfter;

    const idempotencyKey = `idem-restart-${requestId("persist")}`;
    const idemPayload = {
      slug: "nmap",
      method: "run",
      params: {
        target: "restart-idempotency.local",
        client_idempotency_key: idempotencyKey,
      },
      idempotencyKey,
      retryPolicy: {
        retries: 1,
        delayMs: 1000,
        backoffFactor: 2,
      },
    };

    const beforeReplay = await sendJsonRequestSettled(restartNodeId, {
      method: "POST",
      path: "/api/v1/execute",
      principalId: "restart-principal",
      bodyObject: idemPayload,
    });
    await restartNode(restartNodeId, {});
    await advanceTicks(2);
    const afterReplay = await sendJsonRequestSettled(restartNodeId, {
      method: "POST",
      path: "/api/v1/execute",
      principalId: "restart-principal",
      bodyObject: idemPayload,
    });

    const replayBefore = beforeReplay && beforeReplay.json && beforeReplay.json.data ? beforeReplay.json.data.result : null;
    const replayAfter = afterReplay && afterReplay.json && afterReplay.json.data ? afterReplay.json.data.result : null;
    const idempotencyReplayStable = hashStable(replayBefore) === hashStable(replayAfter);

    const sideA = nodeIds.slice(0, Math.floor(nodeIds.length / 2));
    const sideB = nodeIds.slice(Math.floor(nodeIds.length / 2));
    await injectPartition(sideA, sideB);
    await advanceTicks(3);

    const partitionTarget = sideA[0];
    const prePartitionSnapshot = clusterSnapshot(partitionTarget);
    const preBaseline =
      prePartitionSnapshot && prePartitionSnapshot.partition && Number.isFinite(Number(prePartitionSnapshot.partition.entryBaselineSize))
        ? Number(prePartitionSnapshot.partition.entryBaselineSize)
        : 0;
    const preStableDigest = snapshotDigest(prePartitionSnapshot);

    await restartNode(partitionTarget, {});
    await advanceTicks(3);

    const postPartitionSnapshot = clusterSnapshot(partitionTarget);
    const postBaseline =
      postPartitionSnapshot && postPartitionSnapshot.partition && Number.isFinite(Number(postPartitionSnapshot.partition.entryBaselineSize))
        ? Number(postPartitionSnapshot.partition.entryBaselineSize)
        : 0;
    const postStableDigest = snapshotDigest(postPartitionSnapshot);

    const partitionBaselineConsistent = preBaseline > 0 && preBaseline === postBaseline;
    const snapshotConsistent = preStableDigest === postStableDigest && idempotencyReplayStable;

    await resolvePartition();
    await advanceTicks(3);

    return {
      ok: snapshotConsistent && partitionBaselineConsistent && noSpuriousLeaderChange,
      snapshotConsistent,
      partitionBaselineConsistent,
      noSpuriousLeaderChange,
      idempotencyReplayStable,
    };
  }

  async function runRetryBackoffScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length === 0) {
      return {
        ok: false,
        observedDeterministicDelay: false,
      };
    }

    const managerNode = state.clusterManagers.get(nodeIds[0]);
    let ownerNodeId = nodeIds[0];
    if (managerNode && typeof managerNode.resolveOwnerForSlug === "function") {
      const selection = managerNode.resolveOwnerForSlug("nmap");
      if (selection && typeof selection.ownerNodeId === "string" && selection.ownerNodeId) {
        ownerNodeId = selection.ownerNodeId;
      }
    }

    const marker = `retry-marker-${requestId("retry")}`;
    const payload = {
      slug: "nmap",
      method: "run",
      params: {
        target: "retry-backoff.local",
        retry_marker: marker,
        __simulate_transport_failure_once: true,
      },
      retryPolicy: {
        retries: 1,
        delayMs: 1000,
        backoffFactor: 2,
      },
    };

    const firstAttempt = await sendJsonRequestSettled(ownerNodeId, {
      method: "POST",
      path: "/api/v1/execute",
      principalId: "retry-principal",
      bodyObject: payload,
    });

    const beforeWindowExecutions = state.runtimeExecutions.filter((entry) => entry && entry.retryMarker === marker).length;
    await advanceTime(900);
    const midWindowExecutions = state.runtimeExecutions.filter((entry) => entry && entry.retryMarker === marker).length;
    await advanceTime(200);
    const afterWindowExecutions = state.runtimeExecutions.filter((entry) => entry && entry.retryMarker === marker).length;

    const retriesCounter = counterValue(metricsSnapshot(ownerNodeId), "supervisor.retries.count");
    const observedDeterministicDelay = beforeWindowExecutions === 0 && midWindowExecutions === 0 && afterWindowExecutions >= 1;

    return {
      ok: firstAttempt.statusCode >= 400 && observedDeterministicDelay && retriesCounter >= 1,
      observedDeterministicDelay,
      firstAttemptStatusCode: firstAttempt.statusCode,
      retriesCounter,
      beforeWindowExecutions,
      midWindowExecutions,
      afterWindowExecutions,
    };
  }

  async function runRollingUpgradeScenario() {
    const nodeIds = listNodeIds();
    if (nodeIds.length < 3) {
      return {
        ok: false,
        freezeObserved: false,
        freezeBehaviorCorrect: false,
      };
    }

    const targetNodes = nodeIds.slice(0, Math.min(3, nodeIds.length));
    for (let index = 0; index < targetNodes.length; index += 1) {
      const nodeId = targetNodes[index];
      await simulateRollingUpgrade(nodeId, `1.${index + 1}.0`);
      const smoke = await sendJsonRequestSettled(nodeId, {
        method: "POST",
        path: "/api/v1/execute",
        principalId: "upgrade-principal",
        bodyObject: {
          slug: "sim-tool",
          method: "run",
          params: {
            scenario: "rolling-upgrade-smoke",
            index,
          },
        },
      });
      if (smoke.statusCode !== 200) {
        return {
          ok: false,
          freezeObserved: false,
          freezeBehaviorCorrect: false,
        };
      }
    }

    // Version-skew freeze probe from immutable observed snapshots.
    const skewNodes = nodeIds.slice(0, Math.ceil(nodeIds.length / 2));
    for (const nodeId of skewNodes) {
      state.faultInjector.injectVersionSkew(nodeId, "3.0.0");
    }
    await advanceTicks(3);

    const probeNode = nodeIds[nodeIds.length - 1];
    const freezeSnapshot = clusterSnapshot(probeNode);
    const freezeObserved = Boolean(
      freezeSnapshot &&
        freezeSnapshot.upgradeCompatibility &&
        Number(freezeSnapshot.upgradeCompatibility.freezeActive) === 1,
    );
    const leaderSuppressedDuringFreeze = Boolean(freezeSnapshot && freezeSnapshot.leader && freezeSnapshot.leader.transitionsSuppressed === true);

    const rebalanceBefore = counterValue(metricsSnapshot(probeNode), "cluster.shard_rebalance");
    await advanceTicks(1);
    const rebalanceDuring = counterValue(metricsSnapshot(probeNode), "cluster.shard_rebalance");

    for (const nodeId of skewNodes) {
      state.faultInjector.injectVersionSkew(nodeId, "");
    }
    await advanceTicks(4);
    const postFreezeSnapshot = clusterSnapshot(probeNode);
    const freezeReleased =
      postFreezeSnapshot &&
      postFreezeSnapshot.upgradeCompatibility &&
      Number(postFreezeSnapshot.upgradeCompatibility.freezeActive) === 0;
    const rebalanceAfter = counterValue(metricsSnapshot(probeNode), "cluster.shard_rebalance");

    const freezeBehaviorCorrect =
      freezeObserved &&
      leaderSuppressedDuringFreeze &&
      rebalanceDuring === rebalanceBefore &&
      freezeReleased &&
      rebalanceAfter >= rebalanceDuring;

    return {
      ok: true,
      freezeObserved,
      freezeBehaviorCorrect,
    };
  }

  function validateIsolationInvariants() {
    const nodes = state.nodeOrder.map((nodeId) => state.nodes.get(nodeId)).filter(Boolean);
    const metricsRefs = new Set(nodes.map((node) => node.metrics));
    const peerRegistryRefs = new Set(nodes.map((node) => node.peerRegistry));
    const signerRefs = new Set(nodes.map((node) => node.requestSigner));
    const statePaths = new Set(nodes.map((node) => node.statePath));
    const managerRefs = new Set(nodes.map((node) => state.clusterManagers.get(node.nodeId)).filter(Boolean));

    const isolated =
      metricsRefs.size === nodes.length &&
      peerRegistryRefs.size === nodes.length &&
      signerRefs.size === nodes.length &&
      statePaths.size === nodes.length &&
      managerRefs.size === nodes.length;

    if (!isolated) {
      validation.errors.push({
        invariant: "no_hidden_global_state",
        message: "detected shared references across node-local control-plane components",
      });
    }

    return isolated;
  }

  function assert(condition, invariant, message, details = undefined) {
    if (condition) {
      return true;
    }
    validation.errors.push({
      invariant,
      message,
      details: typeof details !== "undefined" ? details : null,
    });
    return false;
  }

  async function runStressSuite(options = {}) {
    assertStarted();
    validation.errors = [];

    const mixedLoad = await runMixedLoadScenario({
      totalRequests: normalizePositiveInt(options.totalRequests, 40),
    });

    validation.mixed_tool_skill_load_stable = assert(
      mixedLoad.ok,
      "mixed_tool_skill_load_stable",
      "mixed tool+skill load did not remain stable",
      mixedLoad,
    );
    validation.no_deadlock_detected = assert(
      mixedLoad.deadlock !== true,
      "no_deadlock_detected",
      "request execution deadlocked or timed out under concurrent load",
      mixedLoad,
    );

    const authSigning = await runAuthSigningScenario();
    assert(
      authSigning.ok === true,
      "auth_signing_enforced",
      "auth/signing middleware validation checks failed",
      authSigning,
    );

    const idempotency = await runIdempotencyScenario();
    validation.idempotency_consistent_across_nodes = assert(
      idempotency.ok,
      "idempotency_consistent_across_nodes",
      "cross-node idempotency consistency check failed",
      idempotency,
    );
    validation.no_duplicate_execution_detected = assert(
      idempotency.noDuplicateExecution === true,
      "no_duplicate_execution_detected",
      "duplicate execution detected for same idempotency marker",
      idempotency,
    );

    const equalSplit = await runEqualSplitScenario();
    validation.no_split_brain_under_partition = assert(
      equalSplit.noSplitBrain === true,
      "no_split_brain_under_partition",
      "equal-split partition did not fully contain active leadership/routing",
      equalSplit,
    );

    const asymmetric = await runAsymmetricPartitionScenario();
    assert(
      asymmetric.ok === true,
      "asymmetric_partition",
      "asymmetric one-way partition behavior did not match expected directional isolation",
      asymmetric,
    );

    const restartScenario = await runRestartPersistenceScenario();
    validation.snapshot_persistence_consistent_after_restart = assert(
      restartScenario.snapshotConsistent === true,
      "snapshot_persistence_consistent_after_restart",
      "stable snapshot or idempotency replay drifted across restart",
      restartScenario,
    );
    validation.no_spurious_leader_change_on_restart = assert(
      restartScenario.noSpuriousLeaderChange === true,
      "no_spurious_leader_change_on_restart",
      "leader changed after restart with unchanged membership",
      restartScenario,
    );
    validation.partition_baseline_consistent_after_restart = assert(
      restartScenario.partitionBaselineConsistent === true,
      "partition_baseline_consistent_after_restart",
      "partition baseline changed after restart while partitioned",
      restartScenario,
    );

    const rollingUpgrade = await runRollingUpgradeScenario();
    validation.rolling_upgrade_invariants_hold = assert(
      rollingUpgrade.ok === true,
      "rolling_upgrade_invariants_hold",
      "rolling upgrade invariant checks failed",
      rollingUpgrade,
    );
    validation.freeze_behavior_correct = assert(
      rollingUpgrade.freezeBehaviorCorrect === true,
      "freeze_behavior_correct",
      "freeze cycle checks did not pass",
      rollingUpgrade,
    );

    const snapshotConsistency = validateSnapshotConsistency();
    validation.snapshot_consistency_preserved = assert(
      snapshotConsistency.ok,
      "snapshot_consistency_preserved",
      "snapshot version drift detected within request lifecycle",
      snapshotConsistency,
    );

    const retryBackoff = await runRetryBackoffScenario();
    validation.retry_backoff_deterministic = assert(
      retryBackoff.ok,
      "retry_backoff_deterministic",
      "retry/backoff timing did not match deterministic clock advancement",
      retryBackoff,
    );

    validation.no_hidden_global_state = assert(
      validateIsolationInvariants(),
      "no_hidden_global_state",
      "node-local global state isolation check failed",
      {},
    );

    const timerErrors = state.clock ? state.clock.getTimerErrors() : [];
    if (timerErrors.length > 0) {
      validation.errors.push({
        invariant: "retry_backoff_deterministic",
        message: "timer callback errors detected during deterministic scheduling",
        details: timerErrors,
      });
    }

    return getValidationReport();
  }

  function getValidationReport() {
    return {
      no_split_brain_under_partition: Boolean(validation.no_split_brain_under_partition),
      no_duplicate_execution_detected: Boolean(validation.no_duplicate_execution_detected),
      freeze_behavior_correct: Boolean(validation.freeze_behavior_correct),
      rolling_upgrade_invariants_hold: Boolean(validation.rolling_upgrade_invariants_hold),
      idempotency_consistent_across_nodes: Boolean(validation.idempotency_consistent_across_nodes),
      snapshot_consistency_preserved: Boolean(validation.snapshot_consistency_preserved),
      snapshot_persistence_consistent_after_restart: Boolean(validation.snapshot_persistence_consistent_after_restart),
      no_spurious_leader_change_on_restart: Boolean(validation.no_spurious_leader_change_on_restart),
      partition_baseline_consistent_after_restart: Boolean(validation.partition_baseline_consistent_after_restart),
      retry_backoff_deterministic: Boolean(validation.retry_backoff_deterministic),
      no_hidden_global_state: Boolean(validation.no_hidden_global_state),
      no_deadlock_detected: Boolean(validation.no_deadlock_detected),
      mixed_tool_skill_load_stable: Boolean(validation.mixed_tool_skill_load_stable),
      errors: deepClone(validation.errors),
    };
  }

  return {
    startCluster,
    stopCluster,
    injectPartition,
    resolvePartition,
    simulateRollingUpgrade,
    runMixedLoadScenario,
    restartNode,
    runStressSuite,
    advanceTime,
    advanceTicks,
    getValidationReport,
    getFaultInjector: () => state.faultInjector,
  };
}

module.exports = {
  createClusterSimulator,
};
