const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { execFile, spawn } = require("node:child_process");
const { promisify } = require("node:util");

const DAEMON_PATH = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills/opencode-daemon/server.js";
const SYNC_SCRIPT_PATH = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/scripts/sync-skill-to-runtime.sh";
const MCP_START_SCRIPT_PATH = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp/scripts/mcp-start-pm2.sh";
const MCP_CWD = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/github-pro-mcp";
const execFileAsync = promisify(execFile);

async function writeFakeOpencode(binDir, options = {}) {
  const scriptPath = path.join(binDir, "opencode");
  const script = `#!/usr/bin/env node
const http = require("node:http");
const args = process.argv.slice(2);
if (args[0] === "serve") {
  const hostIndex = args.indexOf("--hostname");
  const portIndex = args.indexOf("--port");
  const host = hostIndex >= 0 ? args[hostIndex + 1] : "127.0.0.1";
  const port = portIndex >= 0 ? Number(args[portIndex + 1]) : 8090;
  if (process.env.FAKE_OPENCODE_SERVE_FAIL === "1") {
    process.exit(1);
  }
  const sessions = new Map();
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    let body = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch {}
    if (req.method === "GET" && req.url === "/global/health") {
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify({ healthy: true, version: "fake" }));
      return;
    }
    if (req.method === "POST" && req.url === "/session") {
      const id = "oc-" + Date.now();
      sessions.set(id, { id });
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify({ id }));
      return;
    }
    if (req.method === "POST" && /^\\/session\\/[^/]+\\/message$/.test(req.url || "")) {
      const textPart = Array.isArray(body.parts) ? body.parts.find((p) => p && typeof p.text === "string") : null;
      const text = textPart && textPart.text ? textPart.text : "";
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify({ parts: [{ text: "echo:" + text }] }));
      return;
    }
    if (req.method === "DELETE" && /^\\/session\\//.test(req.url || "")) {
      res.writeHead(200, {"content-type":"application/json"});
      res.end(JSON.stringify(true));
      return;
    }
    res.writeHead(404, {"content-type":"application/json"});
    res.end(JSON.stringify({ error: "not found" }));
  });
  server.listen(port, host);
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
  process.on("SIGINT", () => server.close(() => process.exit(0)));
} else if (args[0] === "run") {
  const prompt = args[args.length - 1] || "";
  process.stdout.write(JSON.stringify({ text: "fallback:" + prompt }) + "\\n");
  process.exit(0);
} else {
  process.exit(0);
}
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

async function waitForHealth(url, requireServerHealthy = false) {
  const start = Date.now();
  let lastPayload = null;
  while (Date.now() - start < 15000) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        if (!requireServerHealthy) return;
        const payload = await response.json();
        lastPayload = payload;
        if (payload && payload.opencode_server && payload.opencode_server.healthy === true) {
          return;
        }
      }
    } catch {
      // keep waiting
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Timed out waiting for health at ${url}; last payload=${JSON.stringify(lastPayload)}`);
}

test("opencode daemon session lifecycle works with server backend", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-daemon-e2e-"));
  const binDir = path.join(tempDir, "bin");
  await fs.mkdir(binDir, { recursive: true });
  await writeFakeOpencode(binDir);

  const daemonPort = 18091;
  const serverPort = 18090;
  const env = {
    ...process.env,
    PATH: `${binDir}:${process.env.PATH}`,
    OPENCODE_DAEMON_HOST: "127.0.0.1",
    OPENCODE_DAEMON_PORT: String(daemonPort),
    OPENCODE_SERVER_HOST: "127.0.0.1",
    OPENCODE_SERVER_PORT: String(serverPort),
    OPENCODE_SERVER_BASE_URL: `http://127.0.0.1:${serverPort}`,
    OPENCODE_SESSION_SNAPSHOT: path.join(tempDir, "sessions.json"),
    OPENCODE_MAX_ACTIVE_SESSIONS: "2",
    OPENCODE_QUEUE_MAX: "8",
  };

  const daemon = spawn(process.execPath, [DAEMON_PATH], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let daemonStderr = "";
  daemon.stderr.on("data", (chunk) => {
    daemonStderr += String(chunk || "");
  });

  try {
    try {
      await waitForHealth(`http://127.0.0.1:${daemonPort}/health`, true);
    } catch (error) {
      throw new Error(`${error.message}\nDaemon stderr:\n${daemonStderr}`);
    }

    const created = await fetch(`http://127.0.0.1:${daemonPort}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "e2e" }),
    }).then((res) => res.json());

    assert.equal(created.backend, "server");
    assert.ok(created.session_id);

    const replied = await fetch(`http://127.0.0.1:${daemonPort}/session/${encodeURIComponent(created.session_id)}/message`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: "hello world" }),
    }).then((res) => res.json());

    assert.equal(replied.backend, "server");
    assert.match(String(replied.output), /echo:hello world/);

    const state = await fetch(`http://127.0.0.1:${daemonPort}/session/${encodeURIComponent(created.session_id)}/state`).then((res) => res.json());
    assert.equal(state.message_count, 1);

    const closed = await fetch(`http://127.0.0.1:${daemonPort}/session/${encodeURIComponent(created.session_id)}/close`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }).then((res) => res.json());

    assert.equal(closed.closed, true);
  } finally {
    daemon.kill("SIGTERM");
    await new Promise((resolve) => daemon.once("exit", resolve));
  }
});

test("synced runtime opencode skill wrapper can run full session lifecycle", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-daemon-skill-e2e-"));
  const binDir = path.join(tempDir, "bin");
  await fs.mkdir(binDir, { recursive: true });
  await writeFakeOpencode(binDir);

  const daemonPort = 18291;
  const serverPort = 18290;
  const env = {
    ...process.env,
    PATH: `${binDir}:${process.env.PATH}`,
    OPENCODE_DAEMON_HOST: "127.0.0.1",
    OPENCODE_DAEMON_PORT: String(daemonPort),
    OPENCODE_SERVER_HOST: "127.0.0.1",
    OPENCODE_SERVER_PORT: String(serverPort),
    OPENCODE_SERVER_BASE_URL: `http://127.0.0.1:${serverPort}`,
    OPENCODE_SESSION_SNAPSHOT: path.join(tempDir, "sessions.json"),
  };

  const daemon = spawn(process.execPath, [DAEMON_PATH], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const previousDaemonBaseUrl = process.env.OPENCODE_DAEMON_BASE_URL;
  process.env.OPENCODE_DAEMON_BASE_URL = `http://127.0.0.1:${daemonPort}`;

  try {
    await waitForHealth(`http://127.0.0.1:${daemonPort}/health`, true);
    await execFileAsync("bash", [SYNC_SCRIPT_PATH], {
      cwd: "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge",
      env: process.env,
    });

    const runtimeToolsPath = path.join(os.homedir(), ".openclaw", "skills", "opencode", "tools.js");
    delete require.cache[require.resolve(runtimeToolsPath)];
    const runtimeTools = require(runtimeToolsPath);

    const created = await runtimeTools.opencode_session_create({
      session_id: `skill-e2e-${Date.now()}`,
      title: "skill-wrapper-test",
    });
    assert.equal(typeof created.session_id, "string");
    assert.ok(created.session_id.length > 0);

    const replied = await runtimeTools.opencode_session_message({
      session_id: created.session_id,
      message: "hello from wrapper",
      no_reply: true,
    });
    assert.equal(replied.session_id, created.session_id);
    assert.equal(replied.message_count, 1);

    const state = await runtimeTools.opencode_session_state({ session_id: created.session_id });
    assert.equal(state.session_id, created.session_id);
    assert.equal(state.message_count, 1);

    const closed = await runtimeTools.opencode_session_close({ session_id: created.session_id });
    assert.equal(closed.closed, true);
  } finally {
    if (previousDaemonBaseUrl === undefined) {
      delete process.env.OPENCODE_DAEMON_BASE_URL;
    } else {
      process.env.OPENCODE_DAEMON_BASE_URL = previousDaemonBaseUrl;
    }
    daemon.kill("SIGTERM");
    await new Promise((resolve) => daemon.once("exit", resolve));
  }
});

test("pm2 startup script includes openclaw-mcp and openclaw-opencode-daemon", { skip: process.env.RUN_PM2_ASSERT !== "1" ? "Set RUN_PM2_ASSERT=1 to run PM2 process assertion." : false }, async () => {
  await execFileAsync("bash", [MCP_START_SCRIPT_PATH], {
    cwd: MCP_CWD,
    env: process.env,
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
  });

  const { stdout } = await execFileAsync("pm2", ["jlist"], {
    env: process.env,
    timeout: 30000,
    maxBuffer: 8 * 1024 * 1024,
  });

  const apps = JSON.parse(stdout);
  const names = new Set(apps.map((item) => item && item.name).filter(Boolean));
  assert.equal(names.has("openclaw-mcp"), true);
  assert.equal(names.has("openclaw-opencode-daemon"), true);
});
