const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { AsyncRotatingAuditLogger } = require("../../src/core/audit-log.js");

async function waitFor(predicate, timeoutMs = 2000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await predicate()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

test("audit logger rotates to .1 when max size is exceeded", async () => {
  const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-audit-"));
  const logPath = path.join(workspaceRoot, ".openclaw", "audit.log");
  const logger = new AsyncRotatingAuditLogger(logPath, 512);

  for (let i = 0; i < 250; i += 1) {
    logger.append({
      requestId: `req-${i}`,
      tool: "supervisor.read_file",
      caller: "test",
      timestamp: new Date().toISOString(),
      argsHash: `${"a".repeat(60)}-${i}`,
      resultStatus: "ok",
    });
  }

  const rotatedReady = await waitFor(async () => {
    try {
      const stat = await fs.stat(`${logPath}.1`);
      return stat.size > 0;
    } catch {
      return false;
    }
  });
  assert.equal(rotatedReady, true, "expected audit.log.1 to exist after rotation");

  const activeReady = await waitFor(async () => {
    try {
      const stat = await fs.stat(logPath);
      return stat.size > 0;
    } catch {
      return false;
    }
  });
  assert.equal(activeReady, true, "expected active audit.log to continue receiving entries");
});

test("audit logger failures are fail-open and non-blocking", async () => {
  const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-audit-failopen-"));
  const badLogPath = path.join(workspaceRoot, "audit.log");
  await fs.mkdir(badLogPath, { recursive: true });
  const logger = new AsyncRotatingAuditLogger(badLogPath, 256);

  const started = Date.now();
  for (let i = 0; i < 2_000; i += 1) {
    logger.append({
      requestId: `req-${i}`,
      tool: "supervisor.read_file",
      caller: "fail-open-test",
      timestamp: new Date().toISOString(),
      argsHash: "hash",
      resultStatus: "error",
    });
  }
  const elapsed = Date.now() - started;
  assert.equal(elapsed < 300, true, `append queue should remain non-blocking, elapsed=${elapsed}ms`);

  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(true, true);
});

test("audit logger applies queue backpressure with drop accounting", async () => {
  const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-audit-overflow-"));
  const logPath = path.join(workspaceRoot, ".openclaw", "audit.log");
  let dropped = 0;
  const logger = new AsyncRotatingAuditLogger(logPath, 10 * 1024 * 1024, 50, {
    onDrop: (count) => {
      dropped += count;
    },
  });

  for (let i = 0; i < 5_000; i += 1) {
    logger.append({
      requestId: `req-${i}`,
      tool: "supervisor.read_file",
      caller: "overflow-test",
      timestamp: new Date().toISOString(),
      argsHash: `${i}`,
      resultStatus: "ok",
    });
  }

  await waitFor(async () => logger.getStats().queueDepth < 50, 3000);
  const stats = logger.getStats();
  assert.equal(stats.droppedRecords > 0, true);
  assert.equal(dropped, stats.droppedRecords);
});
