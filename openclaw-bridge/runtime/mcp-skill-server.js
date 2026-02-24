const http = require("node:http");

const { createSkillRuntime } = require("./skill-runtime-core.js");

const DEFAULT_PORT = 4000;
const DEFAULT_EXEC_TIMEOUT_MS = 60_000;
const MAX_BODY_BYTES = 1024 * 1024;

const PORT = Number.parseInt(process.env.PORT || String(DEFAULT_PORT), 10);
const TOOL_NAME = process.env.TOOL_NAME;
const SKILL_SLUG = process.env.SKILL_SLUG;
const MCP_SKILL_TOKEN = typeof process.env.MCP_SKILL_TOKEN === "string" ? process.env.MCP_SKILL_TOKEN.trim() : "";

function parseExecutionTimeoutMs(rawValue) {
  const parsed = Number.parseInt(String(rawValue ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_EXEC_TIMEOUT_MS;
  }
  return parsed;
}

const SKILL_EXECUTION_TIMEOUT_MS = parseExecutionTimeoutMs(process.env.SKILL_EXECUTION_TIMEOUT_MS);

if (!MCP_SKILL_TOKEN) {
  console.error("CRITICAL: MCP_SKILL_TOKEN is required. Refusing to start.");
  process.exit(1);
}

if (!TOOL_NAME || !SKILL_SLUG) {
  console.error("TOOL_NAME and SKILL_SLUG environment variables are required");
  process.exit(1);
}

if (!Number.isFinite(PORT) || PORT <= 0) {
  console.error(`Invalid PORT value: ${process.env.PORT}`);
  process.exit(1);
}

const runtime = createSkillRuntime({
  slug: SKILL_SLUG,
  toolName: TOOL_NAME,
  defaultFlags: "",
  injectHostNet: false,
});

const METHOD_WHITELIST = [
  "run",
  "health",
  "read_output_chunk",
  "search_output",
  "semantic_summary",
  "anomaly_summary",
  "anomaly_diff",
  "tag_baseline",
  "list_baselines",
  "diff_against_baseline",
];

const methodHandlers = {
  run: runtime.run,
  health: runtime.health,
  read_output_chunk: runtime.read_output_chunk,
  search_output: runtime.search_output,
  semantic_summary: runtime.semantic_summary,
  anomaly_summary: runtime.anomaly_summary,
  anomaly_diff: runtime.anomaly_diff,
  tag_baseline: runtime.tag_baseline,
  list_baselines: runtime.list_baselines,
  diff_against_baseline: runtime.diff_against_baseline,
};

const methodSet = new Set(METHOD_WHITELIST);

function getBaseMediaType(contentTypeValue) {
  const raw = typeof contentTypeValue === "string" ? contentTypeValue : "";
  return raw.split(";", 1)[0].trim().toLowerCase();
}

function isJsonContentType(req) {
  return getBaseMediaType(req.headers["content-type"]) === "application/json";
}

function isAuthorized(req) {
  const authHeader = typeof req.headers.authorization === "string" ? req.headers.authorization : "";
  if (!authHeader.startsWith("Bearer ")) {
    return false;
  }
  const token = authHeader.slice("Bearer ".length);
  return token === MCP_SKILL_TOKEN;
}

function createResponder(res) {
  let responded = false;

  const hasResponded = () => responded || res.writableEnded || res.destroyed;

  const send = (statusCode, payload, contentType) => {
    if (hasResponded()) {
      return false;
    }

    const body = typeof payload === "string" ? payload : JSON.stringify(payload);
    responded = true;
    res.writeHead(statusCode, {
      "Content-Type": contentType,
      "Content-Length": Buffer.byteLength(body, "utf8"),
      Connection: "close",
    });
    res.end(body);
    return true;
  };

  return {
    hasResponded,
    sendPlain(statusCode, body) {
      return send(statusCode, body, "text/plain; charset=utf-8");
    },
    sendJson(statusCode, payload) {
      return send(statusCode, payload, "application/json");
    },
  };
}

function sendRpcError(responder, id, code, message) {
  responder.sendJson(200, {
    jsonrpc: "2.0",
    error: {
      code,
      message,
    },
    id: typeof id === "undefined" ? null : id,
  });
}

function sendRpcResult(responder, id, result) {
  responder.sendJson(200, {
    jsonrpc: "2.0",
    result,
    id,
  });
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    let done = false;

    const cleanup = () => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("aborted", onAborted);
    };

    const fail = (error) => {
      if (done) {
        return;
      }
      done = true;
      cleanup();
      reject(error);
    };

    const onData = (chunk) => {
      if (done) {
        return;
      }
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
      totalBytes += buf.length;

      if (totalBytes > MAX_BODY_BYTES) {
        const error = new Error("Request body too large");
        error.code = "BODY_TOO_LARGE";
        done = true;
        cleanup();
        if (req.socket && !req.socket.destroyed) {
          req.socket.destroy();
        }
        reject(error);
        return;
      }

      chunks.push(buf);
    };

    const onEnd = () => {
      if (done) {
        return;
      }
      done = true;
      cleanup();
      resolve(Buffer.concat(chunks).toString("utf8"));
    };

    const onError = (error) => {
      fail(error);
    };

    const onAborted = () => {
      const error = new Error("Request aborted");
      error.code = "REQUEST_ABORTED";
      fail(error);
    };

    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
  });
}

function normalizeJsonRpcErrorId(idValue) {
  if (idValue === null || typeof idValue === "string" || typeof idValue === "number") {
    return idValue;
  }
  return null;
}

function validateRpcPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {
      ok: false,
      code: -32600,
      message: "Invalid Request",
      id: null,
    };
  }

  const hasId = Object.prototype.hasOwnProperty.call(payload, "id");
  if (!hasId) {
    return {
      ok: false,
      code: -32600,
      message: "Invalid Request",
      id: null,
    };
  }

  const id = normalizeJsonRpcErrorId(payload.id);
  if (id === null && payload.id !== null) {
    return {
      ok: false,
      code: -32600,
      message: "Invalid Request",
      id: null,
    };
  }

  if (payload.jsonrpc !== "2.0" || typeof payload.method !== "string") {
    return {
      ok: false,
      code: -32600,
      message: "Invalid Request",
      id,
    };
  }

  if (!methodSet.has(payload.method)) {
    return {
      ok: false,
      code: -32601,
      message: "Method Not Found",
      id,
    };
  }

  const params = Object.prototype.hasOwnProperty.call(payload, "params") ? payload.params : {};
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    return {
      ok: false,
      code: -32600,
      message: "Invalid Request",
      id,
    };
  }

  return {
    ok: true,
    id,
    method: payload.method,
    params,
  };
}

async function executeWithTimeout(handler, params, timeoutMs) {
  const runtimePromise = Promise.resolve().then(() => handler(params));
  runtimePromise.catch(() => {});

  let timeoutHandle;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => {
      const error = new Error("Execution Timeout");
      error.code = "EXECUTION_TIMEOUT";
      reject(error);
    }, timeoutMs);
  });

  try {
    return await Promise.race([runtimePromise, timeoutPromise]);
  } finally {
    clearTimeout(timeoutHandle);
  }
}

const server = http.createServer(async (req, res) => {
  const responder = createResponder(res);

  if (req.url !== "/mcp") {
    responder.sendPlain(404, "Not Found");
    return;
  }

  if (req.method !== "POST") {
    responder.sendPlain(405, "Method Not Allowed");
    return;
  }

  if (!isJsonContentType(req)) {
    responder.sendPlain(415, "Unsupported Media Type");
    return;
  }

  if (!isAuthorized(req)) {
    responder.sendPlain(401, "Unauthorized");
    return;
  }

  let rawBody;
  try {
    rawBody = await readRequestBody(req);
  } catch (error) {
    if (error && error.code === "BODY_TOO_LARGE") {
      return;
    }
    if (error && error.code === "REQUEST_ABORTED") {
      return;
    }
    sendRpcError(responder, null, -32603, "Internal error");
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    sendRpcError(responder, null, -32700, "Parse error");
    return;
  }

  const validation = validateRpcPayload(payload);
  if (!validation.ok) {
    sendRpcError(responder, validation.id, validation.code, validation.message);
    return;
  }

  const handler = methodHandlers[validation.method];

  try {
    const result = await executeWithTimeout(handler, validation.params, SKILL_EXECUTION_TIMEOUT_MS);
    sendRpcResult(responder, validation.id, result);
  } catch (error) {
    if (error && error.code === "EXECUTION_TIMEOUT") {
      sendRpcError(responder, validation.id, -32603, "Execution Timeout");
      return;
    }
    sendRpcError(responder, validation.id, -32603, "Internal error");
  }
});

server.listen(PORT, () => {
  console.log(`MCP skill server listening on port ${PORT}`);
});
