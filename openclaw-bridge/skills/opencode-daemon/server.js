/* eslint-disable no-console */

const express = require("express");
const { execFile, spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

const APP_START_TS = Date.now();
const DAEMON_HOST = process.env.OPENCODE_DAEMON_HOST || "127.0.0.1";
const DAEMON_PORT = Number.parseInt(process.env.OPENCODE_DAEMON_PORT || "8091", 10);
const OPENCODE_SERVER_HOST = process.env.OPENCODE_SERVER_HOST || "127.0.0.1";
const OPENCODE_SERVER_PORT = Number.parseInt(process.env.OPENCODE_SERVER_PORT || "8090", 10);
const OPENCODE_SERVER_BASE_URL =
  (process.env.OPENCODE_SERVER_BASE_URL || `http://${OPENCODE_SERVER_HOST}:${OPENCODE_SERVER_PORT}`).replace(/\/+$/, "");
const OPENCODE_DEFAULT_MODEL = process.env.OPENCODE_DEFAULT_MODEL || "ollama/openthinker:7b";
const OPENCODE_OLLAMA_BASE_URL = process.env.OPENCLAW_GATEWAY_BASE_URL || "http://localhost:11434/v1";
const OPENCODE_DEFAULT_AGENT = process.env.OPENCODE_DEFAULT_AGENT || "build";
const OPENCODE_MESSAGE_TIMEOUT_MS = Number.parseInt(process.env.OPENCODE_MESSAGE_TIMEOUT_MS || "120000", 10);
const OPENCODE_QUEUE_MAX = Number.parseInt(process.env.OPENCODE_QUEUE_MAX || "8", 10);
const OPENCODE_MAX_ACTIVE_SESSIONS = Number.parseInt(process.env.OPENCODE_MAX_ACTIVE_SESSIONS || "2", 10);
const RUNTIME_DIR = path.join(__dirname, ".runtime");
const SNAPSHOT_PATH = process.env.OPENCODE_SESSION_SNAPSHOT || path.join(RUNTIME_DIR, "sessions.json");
const MAX_HISTORY_ITEMS = 200;

const sessions = new Map();
const pendingQueue = [];
let activeMessages = 0;
let totalMessages = 0;
let fallbackCount = 0;
let opencodeServerFailures = 0;
let opencodeServerProc = null;
let opencodeServerHealthy = false;
let opencodeServerStdoutTail = "";
let opencodeServerStderrTail = "";

function buildDefaultOpencodeConfigContent() {
  return JSON.stringify({
    $schema: "https://opencode.ai/config.json",
    model: OPENCODE_DEFAULT_MODEL,
    provider: {
      ollama: {
        npm: "@ai-sdk/openai-compatible",
        name: "Ollama (local)",
        options: {
          baseURL: OPENCODE_OLLAMA_BASE_URL,
        },
        models: {
          "openthinker:7b": {
            name: "OpenThinker 7B",
          },
        },
      },
    },
  });
}

function getOpencodeEnv() {
  const env = { ...process.env };
  if (!String(env.OPENCODE_CONFIG_CONTENT || "").trim()) {
    env.OPENCODE_CONFIG_CONTENT = buildDefaultOpencodeConfigContent();
  }
  return env;
}

function appendTail(current, next, maxLen = 2000) {
  const merged = `${current}${String(next || "")}`;
  if (merged.length <= maxLen) {
    return merged;
  }
  return merged.slice(merged.length - maxLen);
}

function parseBool(value, fallback = false) {
  if (typeof value !== "string") return fallback;
  const lowered = value.trim().toLowerCase();
  return lowered === "1" || lowered === "true" || lowered === "yes";
}

function sanitizeSession(session) {
  return {
    session_id: session.id,
    backend: session.backend,
    opencode_session_id: session.opencodeSessionId || null,
    title: session.title || null,
    status: session.status,
    created_at: session.createdAt,
    updated_at: session.updatedAt,
    message_count: session.messageCount,
    last_error: session.lastError || null,
    history: session.history,
  };
}

async function ensureRuntimeDir() {
  await fs.mkdir(RUNTIME_DIR, { recursive: true });
}

async function loadSnapshots() {
  try {
    const raw = await fs.readFile(SNAPSHOT_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return;
    for (const entry of parsed) {
      if (!entry || typeof entry !== "object") continue;
      if (entry.status !== "open") continue;
      const id = String(entry.session_id || entry.id || "").trim();
      if (!id) continue;
      sessions.set(id, {
        id,
        backend: entry.backend === "subprocess" ? "subprocess" : "server",
        opencodeSessionId: entry.opencode_session_id || null,
        title: entry.title || "",
        status: "open",
        createdAt: Number(entry.created_at) || Date.now(),
        updatedAt: Number(entry.updated_at) || Date.now(),
        messageCount: Number(entry.message_count) || 0,
        lastError: entry.last_error || "",
        history: Array.isArray(entry.history) ? entry.history.slice(-MAX_HISTORY_ITEMS) : [],
      });
    }
  } catch {
    // Snapshot recovery is optional.
  }
}

async function saveSnapshots() {
  const payload = Array.from(sessions.values()).map((session) => sanitizeSession(session));
  await fs.writeFile(SNAPSHOT_PATH, JSON.stringify(payload, null, 2), "utf8");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, options = {}, timeoutMs = 12000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }
    return { ok: response.ok, status: response.status, data, raw: text };
  } finally {
    clearTimeout(timer);
  }
}

async function pingOpencodeServer() {
  try {
    const health = await fetchJson(`${OPENCODE_SERVER_BASE_URL}/global/health`, { method: "GET", headers: {} }, 2500);
    opencodeServerHealthy = Boolean(health.ok);
    if (!health.ok) {
      opencodeServerFailures += 1;
    }
    return opencodeServerHealthy;
  } catch (error) {
    opencodeServerHealthy = false;
    opencodeServerFailures += 1;
    opencodeServerStderrTail = appendTail(opencodeServerStderrTail, `\n${error.message || String(error)}`);
    return false;
  }
}

function spawnOpencodeServer() {
  if (opencodeServerProc && !opencodeServerProc.killed) {
    return;
  }

  opencodeServerProc = spawn(
    "opencode",
    ["serve", "--hostname", OPENCODE_SERVER_HOST, "--port", String(OPENCODE_SERVER_PORT)],
    {
      env: getOpencodeEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  opencodeServerProc.stdout.on("data", (chunk) => {
    opencodeServerStdoutTail = appendTail(opencodeServerStdoutTail, chunk.toString("utf8"));
  });

  opencodeServerProc.stderr.on("data", (chunk) => {
    opencodeServerStderrTail = appendTail(opencodeServerStderrTail, chunk.toString("utf8"));
  });

  opencodeServerProc.on("exit", (code, signal) => {
    opencodeServerProc = null;
    opencodeServerHealthy = false;
    opencodeServerFailures += 1;
    opencodeServerStderrTail = appendTail(opencodeServerStderrTail, `\nopencode serve exited code=${code} signal=${signal}`);
  });
}

async function ensureOpencodeServer() {
  spawnOpencodeServer();

  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (await pingOpencodeServer()) {
      return true;
    }
    await sleep(500);
  }

  return false;
}

function withQueue(task) {
  return new Promise((resolve, reject) => {
    const run = async () => {
      activeMessages += 1;
      try {
        const result = await task();
        resolve(result);
      } catch (error) {
        reject(error);
      } finally {
        activeMessages -= 1;
        while (activeMessages < OPENCODE_MAX_ACTIVE_SESSIONS && pendingQueue.length > 0) {
          const next = pendingQueue.shift();
          next();
        }
      }
    };

    if (activeMessages < OPENCODE_MAX_ACTIVE_SESSIONS) {
      run();
      return;
    }

    if (pendingQueue.length >= OPENCODE_QUEUE_MAX) {
      const queueError = new Error(`OpenCode queue is full (${OPENCODE_QUEUE_MAX})`);
      queueError.code = "QUEUE_FULL";
      reject(queueError);
      return;
    }

    pendingQueue.push(run);
  });
}

function normalizeTextFromResponse(data) {
  if (!data || typeof data !== "object") return "";

  const parts = Array.isArray(data.parts) ? data.parts : [];
  const text = [];
  for (const part of parts) {
    if (!part || typeof part !== "object") continue;
    if (typeof part.text === "string") {
      text.push(part.text);
      continue;
    }
    if (typeof part.content === "string") {
      text.push(part.content);
    }
  }

  if (text.length > 0) {
    return text.join("\n").trim();
  }

  if (typeof data.output_text === "string") {
    return data.output_text;
  }

  return "";
}

function parseFallbackOutput(stdout, stderr) {
  const out = String(stdout || "").trim();
  const err = String(stderr || "").trim();
  const lines = out.split("\n").map((line) => line.trim()).filter(Boolean);
  let parsed = null;

  for (let i = lines.length - 1; i >= 0; i -= 1) {
    try {
      parsed = JSON.parse(lines[i]);
      break;
    } catch {
      // ignore parse errors
    }
  }

  if (parsed && typeof parsed === "object") {
    if (typeof parsed.text === "string") {
      return { parsed, text: parsed.text.trim() };
    }
    if (typeof parsed.output_text === "string") {
      return { parsed, text: parsed.output_text.trim() };
    }
  }

  return { parsed: parsed || { stdout: out, stderr: err }, text: out || err };
}

async function callServerCreateSession(session) {
  const healthy = await ensureOpencodeServer();
  if (!healthy) {
    throw new Error("OpenCode server did not become healthy in time");
  }

  const response = await fetchJson(
    `${OPENCODE_SERVER_BASE_URL}/session`,
    {
      method: "POST",
      body: JSON.stringify({ title: session.title || undefined }),
    },
    12000,
  );

  if (!response.ok) {
    throw new Error(`OpenCode session creation failed (${response.status})`);
  }

  const opencodeId = response.data && response.data.id ? String(response.data.id) : "";
  if (!opencodeId) {
    throw new Error("OpenCode session response did not include an id");
  }

  session.opencodeSessionId = opencodeId;
}

async function runFallbackMessage(sessionId, message, opts = {}) {
  const args = [
    "run",
    "--session",
    sessionId,
    "--model",
    opts.model || OPENCODE_DEFAULT_MODEL,
    "--format",
    "json",
    message,
  ];

  if (opts.agent) {
    args.splice(args.length - 1, 0, "--agent", opts.agent);
  }

  return new Promise((resolve, reject) => {
    execFile("opencode", args, {
      env: getOpencodeEnv(),
      timeout: OPENCODE_MESSAGE_TIMEOUT_MS,
      maxBuffer: 32 * 1024 * 1024,
    }, (error, stdout, stderr) => {
      if (error) {
        const detail = `${stderr || ""} ${stdout || ""}`.trim();
        reject(new Error(`OpenCode fallback subprocess failed: ${detail || error.message}`));
        return;
      }
      const parsed = parseFallbackOutput(stdout, stderr);
      resolve({
        backend: "subprocess",
        output: parsed.text,
        raw: parsed.parsed,
      });
    });
  });
}

async function runServerMessage(session, payload) {
  if (!session.opencodeSessionId) {
    await callServerCreateSession(session);
  }

  const message = String(payload.message || payload.prompt || "").trim();
  if (!message) {
    throw new Error("message is required");
  }
  const noReply = Boolean(payload.noReply || payload.no_reply);
  if (noReply) {
    return {
      backend: "server",
      output: "",
      raw: {
        no_reply: true,
        accepted: true,
      },
    };
  }

  const body = {
    model: payload.model || OPENCODE_DEFAULT_MODEL,
    agent: payload.agent || OPENCODE_DEFAULT_AGENT,
    system: typeof payload.system === "string" ? payload.system : undefined,
    noReply,
    parts: Array.isArray(payload.parts)
      ? payload.parts
      : [{ type: "text", text: message }],
  };

  const response = await fetchJson(
    `${OPENCODE_SERVER_BASE_URL}/session/${encodeURIComponent(session.opencodeSessionId)}/message`,
    {
      method: "POST",
      body: JSON.stringify(body),
    },
    OPENCODE_MESSAGE_TIMEOUT_MS,
  );

  if (!response.ok) {
    throw new Error(`OpenCode server message failed (${response.status})`);
  }

  return {
    backend: "server",
    output: normalizeTextFromResponse(response.data),
    raw: response.data,
  };
}

async function closeServerSession(session) {
  if (!session.opencodeSessionId) return;
  await fetchJson(
    `${OPENCODE_SERVER_BASE_URL}/session/${encodeURIComponent(session.opencodeSessionId)}`,
    { method: "DELETE" },
    5000,
  ).catch(() => {
    // Best effort cleanup.
  });
}

function buildMetrics() {
  const openSessions = Array.from(sessions.values()).filter((session) => session.status === "open").length;
  const uptimeSeconds = Math.floor((Date.now() - APP_START_TS) / 1000);

  return [
    "# HELP opencode_daemon_uptime_seconds Uptime of the OpenCode daemon in seconds.",
    "# TYPE opencode_daemon_uptime_seconds gauge",
    `opencode_daemon_uptime_seconds ${uptimeSeconds}`,
    "# HELP opencode_sessions_open Number of currently open sessions.",
    "# TYPE opencode_sessions_open gauge",
    `opencode_sessions_open ${openSessions}`,
    "# HELP opencode_messages_total Total processed session message requests.",
    "# TYPE opencode_messages_total counter",
    `opencode_messages_total ${totalMessages}`,
    "# HELP opencode_fallback_total Number of server-to-subprocess fallback invocations.",
    "# TYPE opencode_fallback_total counter",
    `opencode_fallback_total ${fallbackCount}`,
    "# HELP opencode_queue_size Number of currently queued message jobs.",
    "# TYPE opencode_queue_size gauge",
    `opencode_queue_size ${pendingQueue.length}`,
    "# HELP opencode_active_messages Number of currently running message jobs.",
    "# TYPE opencode_active_messages gauge",
    `opencode_active_messages ${activeMessages}`,
    "# HELP opencode_server_healthy OpenCode server health status (1 healthy, 0 unhealthy).",
    "# TYPE opencode_server_healthy gauge",
    `opencode_server_healthy ${opencodeServerHealthy ? 1 : 0}`,
    "# HELP opencode_server_failures_total Number of OpenCode server health or process failures.",
    "# TYPE opencode_server_failures_total counter",
    `opencode_server_failures_total ${opencodeServerFailures}`,
  ].join("\n");
}

function createSession(payload = {}) {
  const sessionId = String(payload.session_id || payload.sessionId || randomUUID()).trim();
  if (!sessionId) {
    throw new Error("session_id could not be resolved");
  }

  if (sessions.has(sessionId)) {
    throw new Error(`session_id already exists: ${sessionId}`);
  }

  const now = Date.now();
  const session = {
    id: sessionId,
    backend: "server",
    opencodeSessionId: null,
    title: String(payload.title || "").trim(),
    status: "open",
    createdAt: now,
    updatedAt: now,
    messageCount: 0,
    lastError: "",
    history: [],
  };

  sessions.set(sessionId, session);
  return session;
}

function appendHistory(session, entry) {
  session.history.push(entry);
  if (session.history.length > MAX_HISTORY_ITEMS) {
    session.history.splice(0, session.history.length - MAX_HISTORY_ITEMS);
  }
}

async function boot() {
  await ensureRuntimeDir();
  await loadSnapshots();
  await ensureOpencodeServer();

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/health", async (_req, res) => {
    const serverHealthy = await pingOpencodeServer();
    res.json({
      ok: true,
      daemon: {
        host: DAEMON_HOST,
        port: DAEMON_PORT,
        uptime_seconds: Math.floor((Date.now() - APP_START_TS) / 1000),
      },
      opencode_server: {
        base_url: OPENCODE_SERVER_BASE_URL,
        healthy: serverHealthy,
        pid: opencodeServerProc ? opencodeServerProc.pid : null,
        stderr_tail: opencodeServerStderrTail,
      },
      queue: {
        active: activeMessages,
        queued: pendingQueue.length,
        max_active_sessions: OPENCODE_MAX_ACTIVE_SESSIONS,
        max_queue: OPENCODE_QUEUE_MAX,
      },
      sessions_open: Array.from(sessions.values()).filter((session) => session.status === "open").length,
    });
  });

  app.post("/session", async (req, res) => {
    try {
      const session = createSession(req.body || {});
      try {
        await callServerCreateSession(session);
      } catch (error) {
        session.backend = "subprocess";
        session.lastError = error.message || String(error);
      }

      await saveSnapshots();

      res.status(201).json({
        session_id: session.id,
        backend: session.backend,
        opencode_session_id: session.opencodeSessionId,
        created_at: session.createdAt,
      });
    } catch (error) {
      res.status(400).json({ error: error.message || String(error) });
    }
  });

  app.post("/session/:id/message", async (req, res) => {
    const session = sessions.get(String(req.params.id || ""));
    if (!session || session.status !== "open") {
      res.status(404).json({ error: "session not found" });
      return;
    }

    const message = String(req.body?.message || req.body?.prompt || "").trim();
    if (!message) {
      res.status(400).json({ error: "message is required" });
      return;
    }

    try {
      const result = await withQueue(async () => {
        const startedAt = Date.now();
        let output;

        if (session.backend === "server") {
          try {
            output = await runServerMessage(session, req.body || {});
          } catch (error) {
            fallbackCount += 1;
            session.lastError = error.message || String(error);
            output = await runFallbackMessage(session.id, message, req.body || {});
          }
        } else {
          output = await runFallbackMessage(session.id, message, req.body || {});
        }

        const finishedAt = Date.now();
        session.messageCount += 1;
        session.updatedAt = finishedAt;
        appendHistory(session, {
          timestamp: finishedAt,
          prompt: message,
          backend: output.backend,
          output: String(output.output || "").slice(0, 5000),
          duration_ms: finishedAt - startedAt,
        });
        totalMessages += 1;
        await saveSnapshots();

        return {
          session_id: session.id,
          backend: output.backend,
          opencode_session_id: session.opencodeSessionId,
          message_count: session.messageCount,
          output: output.output,
          raw: output.raw,
        };
      });

      res.json(result);
    } catch (error) {
      if (error && error.code === "QUEUE_FULL") {
        res.status(429).json({ error: error.message || String(error) });
        return;
      }
      res.status(500).json({ error: error.message || String(error) });
    }
  });

  app.get("/session/:id/state", (req, res) => {
    const session = sessions.get(String(req.params.id || ""));
    if (!session) {
      res.status(404).json({ error: "session not found" });
      return;
    }

    res.json(sanitizeSession(session));
  });

  app.post("/session/:id/close", async (req, res) => {
    const session = sessions.get(String(req.params.id || ""));
    if (!session) {
      res.status(404).json({ error: "session not found" });
      return;
    }

    session.status = "closed";
    session.updatedAt = Date.now();
    if (session.backend === "server") {
      await closeServerSession(session);
    }
    sessions.delete(session.id);
    await saveSnapshots();

    res.json({ closed: true, session_id: req.params.id });
  });

  app.get("/metrics", (_req, res) => {
    res.type("text/plain").send(`${buildMetrics()}\n`);
  });

  app.listen(DAEMON_PORT, DAEMON_HOST, () => {
    console.log(`opencode-daemon listening on http://${DAEMON_HOST}:${DAEMON_PORT}`);
  });

  const shutdown = () => {
    if (opencodeServerProc && !opencodeServerProc.killed) {
      opencodeServerProc.kill("SIGTERM");
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

boot().catch((error) => {
  console.error(error);
  process.exit(1);
});
