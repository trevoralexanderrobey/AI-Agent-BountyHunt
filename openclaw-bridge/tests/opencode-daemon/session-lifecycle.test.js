const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");

const DAEMON_PATH = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills/opencode-daemon/server.js";

async function writeFallbackOnlyOpencode(binDir) {
  const scriptPath = path.join(binDir, "opencode");
  const script = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "serve") {
  process.exit(1);
}
if (args[0] === "run") {
  const prompt = args[args.length - 1] || "";
  process.stdout.write(JSON.stringify({ text: "fallback:" + prompt }) + "\\n");
  process.exit(0);
}
process.exit(0);
`;
  await fs.writeFile(scriptPath, script, { mode: 0o755 });
  return scriptPath;
}

async function waitForHealth(url) {
  const start = Date.now();
  while (Date.now() - start < 15000) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // keep waiting
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Timed out waiting for health at ${url}`);
}

test("opencode daemon falls back to subprocess mode when server is unavailable", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-daemon-fallback-"));
  const binDir = path.join(tempDir, "bin");
  await fs.mkdir(binDir, { recursive: true });
  await writeFallbackOnlyOpencode(binDir);

  const daemonPort = 18191;
  const serverPort = 18190;
  const env = {
    ...process.env,
    PATH: `${binDir}:${process.env.PATH}`,
    OPENCODE_DAEMON_HOST: "127.0.0.1",
    OPENCODE_DAEMON_PORT: String(daemonPort),
    OPENCODE_SERVER_HOST: "127.0.0.1",
    OPENCODE_SERVER_PORT: String(serverPort),
    OPENCODE_SERVER_BASE_URL: `http://127.0.0.1:${serverPort}`,
    OPENCODE_SESSION_SNAPSHOT: path.join(tempDir, "sessions.json"),
    OPENCODE_MAX_ACTIVE_SESSIONS: "1",
    OPENCODE_QUEUE_MAX: "4",
  };

  const daemon = spawn(process.execPath, [DAEMON_PATH], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForHealth(`http://127.0.0.1:${daemonPort}/health`);

    const created = await fetch(`http://127.0.0.1:${daemonPort}/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "fallback-test" }),
    }).then((res) => res.json());

    assert.equal(created.backend, "subprocess");

    const replied = await fetch(`http://127.0.0.1:${daemonPort}/session/${encodeURIComponent(created.session_id)}/message`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: "needs fallback" }),
    }).then((res) => res.json());

    assert.equal(replied.backend, "subprocess");
    assert.match(String(replied.output), /fallback:needs fallback/);

    const state = await fetch(`http://127.0.0.1:${daemonPort}/session/${encodeURIComponent(created.session_id)}/state`).then((res) => res.json());
    assert.equal(state.backend, "subprocess");
    assert.equal(state.message_count, 1);
  } finally {
    daemon.kill("SIGTERM");
    await new Promise((resolve) => daemon.once("exit", resolve));
  }
});
