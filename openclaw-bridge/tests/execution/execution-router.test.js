const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { createExecutionRouter } = require("../../src/core/execution-router.js");

async function makeWorkspace() {
  const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-router-"));
  await fs.mkdir(path.join(workspaceRoot, ".cline"), { recursive: true });
  await fs.mkdir(path.join(workspaceRoot, ".openclaw"), { recursive: true });
  return workspaceRoot;
}

async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeTokenConfig(workspaceRoot, token) {
  const filePath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify({ token }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await fs.chmod(filePath, 0o600);
}

async function makeRegistry(workspaceRoot) {
  const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
  await writeJson(registryPath, [
    {
      name: "supervisor.read_file",
      description: "read file",
      inputSchema: { type: "object", properties: { path: { type: "string", minLength: 1 } }, required: ["path"], additionalProperties: false },
      mutationClass: "read",
      loggingLevel: "info",
      roles: ["supervisor", "internal", "admin"],
      workspacePathArgs: ["path"],
    },
    {
      name: "supervisor.write_file",
      description: "write file",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", minLength: 1 },
          content: { type: "string" },
          createParents: { type: "boolean" },
        },
        required: ["path", "content"],
        additionalProperties: false,
      },
      mutationClass: "write",
      loggingLevel: "warn",
      roles: ["supervisor", "internal", "admin"],
      workspacePathArgs: ["path"],
    },
    {
      name: "supervisor.internal_only",
      description: "internal-only test tool",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      mutationClass: "read",
      loggingLevel: "info",
      roles: ["internal", "admin"],
    },
    {
      name: "supervisor.admin_only",
      description: "admin-only test tool",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      mutationClass: "read",
      loggingLevel: "info",
      roles: ["admin"],
    },
  ]);
  return registryPath;
}

function makeRouter(workspaceRoot, registryPath, overrides = {}) {
  return createExecutionRouter({
    workspaceRoot,
    registryPath,
    auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
    supervisorMode: false,
    supervisorAuthPhase: "compat",
    supervisorInternalToken: "internal-secret",
    legacyVisibleToolsByRole: {
      supervisor: ["bridge_health"],
      internal: ["bridge_health", "bridge_execute_tool"],
      admin: ["bridge_health", "bridge_execute_tool"],
      anonymous: [],
    },
    ...overrides,
  });
}

test("supervisor.read_file succeeds inside workspace and denies outside", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  await fs.mkdir(path.join(workspaceRoot, "notes"), { recursive: true });
  await fs.writeFile(path.join(workspaceRoot, "notes", "inside.txt"), "inside-content", "utf8");

  const outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-router-outside-"));
  const outsidePath = path.join(outsideRoot, "outside.txt");
  await fs.writeFile(outsidePath, "outside-content", "utf8");

  const router = makeRouter(workspaceRoot, registryPath);
  const baseContext = {
    requestId: "req-1",
    workspaceRoot,
    source: "http_api",
    caller: "test",
    authHeader: "Bearer supervisor-token",
  };

  const inside = await router.execute("supervisor.read_file", { path: "notes/inside.txt" }, baseContext);
  assert.equal(inside.ok, true);
  assert.equal(inside.data.content, "inside-content");

  const traversal = await router.execute("supervisor.read_file", { path: "../../../etc/passwd" }, baseContext);
  assert.equal(traversal.ok, false);
  assert.equal(traversal.code, "PATH_OUTSIDE_WORKSPACE");

  const outside = await router.execute("supervisor.read_file", { path: outsidePath }, baseContext);
  assert.equal(outside.ok, false);
  assert.equal(outside.code, "PATH_OUTSIDE_WORKSPACE");
});

test("legacy execution path remains available when supervisor mode is disabled", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    supervisorMode: false,
  });

  const result = await router.execute("legacy.fake_tool", { sample: true }, {
    requestId: "legacy-1",
    workspaceRoot,
    source: "mcp_sse",
    caller: "legacy-test",
    authHeader: "Bearer supervisor-token",
    legacyExecute: async (tool, args) => ({ tool, args, legacy: true }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.data.legacy, true);
  assert.equal(result.data.tool, "legacy.fake_tool");
});

test("spoofed internal flag is rejected without trusted token", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  await fs.writeFile(path.join(workspaceRoot, "inside.txt"), "x", "utf8");
  const router = makeRouter(workspaceRoot, registryPath);

  const result = await router.execute("supervisor.read_file", { path: "inside.txt" }, {
    requestId: "spoof-1",
    workspaceRoot,
    source: "http_api",
    caller: "spoof-test",
    internalFlagRequested: true,
    authHeader: "Bearer supervisor-token",
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "UNAUTHORIZED_INTERNAL_BYPASS");
});

test("valid internal token grants internal bypass role", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await fs.writeFile(path.join(workspaceRoot, "inside.txt"), "internal-ok", "utf8");
  const router = makeRouter(workspaceRoot, registryPath, {
    supervisorMode: true,
    supervisorAuthPhase: "strict",
  });

  const result = await router.execute("supervisor.read_file", { path: "inside.txt" }, {
    requestId: "internal-1",
    workspaceRoot,
    source: "in_process",
    caller: "internal-worker",
    internalFlagRequested: true,
    internalToken: "internal-secret",
  });

  assert.equal(result.ok, true);
  assert.equal(result.data.content, "internal-ok");
});

test("workspace-relative token lookup overrides fallback env token", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "workspace-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const previous = process.env.BRIDGE_AUTH_TOKEN;
  process.env.BRIDGE_AUTH_TOKEN = "fallback-token";
  try {
    const roleWorkspace = await router.resolveRole({
      requestId: "role-1",
      workspaceRoot,
      source: "mcp_sse",
      caller: "role-test",
      authHeader: "Bearer workspace-token",
    });
    assert.equal(roleWorkspace, "supervisor");

    const roleFallbackOnly = await router.resolveRole({
      requestId: "role-2",
      workspaceRoot,
      source: "mcp_sse",
      caller: "role-test",
      authHeader: "Bearer fallback-token",
    });
    assert.equal(roleFallbackOnly, "anonymous");
  } finally {
    if (typeof previous === "undefined") {
      delete process.env.BRIDGE_AUTH_TOKEN;
    } else {
      process.env.BRIDGE_AUTH_TOKEN = previous;
    }
  }
});

test("tools/list is role-aware and preserves legacy compatibility by role", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const legacyListTools = async () => [
    { name: "bridge_health" },
    { name: "bridge_execute_tool" },
  ];

  const anonymousTools = await router.listTools({
    requestId: "list-anon",
    workspaceRoot,
    source: "mcp_sse",
    caller: "anon",
    legacyListTools,
  });
  const anonymousNames = anonymousTools.map((entry) => entry.name).sort();
  assert.deepEqual(anonymousNames, []);

  const supervisorTools = await router.listTools({
    requestId: "list-supervisor",
    workspaceRoot,
    source: "mcp_sse",
    caller: "supervisor",
    authHeader: "Bearer supervisor-token",
    legacyListTools,
  });
  const supervisorNames = supervisorTools.map((entry) => entry.name);
  assert.equal(supervisorNames.includes("supervisor.read_file"), true);
  assert.equal(supervisorNames.includes("supervisor.internal_only"), false);
  assert.equal(supervisorNames.includes("supervisor.admin_only"), false);
  assert.equal(supervisorNames.includes("bridge_health"), true);
  assert.equal(supervisorNames.includes("bridge_execute_tool"), false);

  const internalTools = await router.listTools({
    requestId: "list-internal",
    workspaceRoot,
    source: "in_process",
    caller: "internal",
    trustedInProcessCaller: true,
    legacyListTools,
  });
  const internalNames = internalTools.map((entry) => entry.name);
  assert.equal(internalNames.includes("supervisor.read_file"), true);
  assert.equal(internalNames.includes("supervisor.internal_only"), true);
  assert.equal(internalNames.includes("supervisor.admin_only"), false);
  assert.equal(internalNames.includes("bridge_execute_tool"), true);
});

test("strict mode rejects anonymous and blocks legacy fallback for external supervisor", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const previousAdminToken = process.env.SUPERVISOR_ADMIN_TOKEN;
  process.env.SUPERVISOR_ADMIN_TOKEN = "admin-token";
  const router = makeRouter(workspaceRoot, registryPath, {
    supervisorMode: true,
    supervisorAuthPhase: "strict",
  });

  try {
    const anonymousResult = await router.execute("supervisor.read_file", { path: "notes/inside.txt" }, {
      requestId: "strict-anon",
      workspaceRoot,
      source: "http_api",
      caller: "anon",
    });
    assert.equal(anonymousResult.ok, false);
    assert.equal(anonymousResult.code, "UNAUTHORIZED");

    const strictLegacy = await router.execute("legacy.fake_tool", {}, {
      requestId: "strict-legacy",
      workspaceRoot,
      source: "mcp_sse",
      caller: "supervisor",
      authHeader: "Bearer supervisor-token",
      legacyExecute: async () => ({ ok: true }),
    });
    assert.equal(strictLegacy.ok, false);
    assert.equal(strictLegacy.code, "UNAUTHORIZED_TOOL");

    const strictLegacyAdmin = await router.execute("legacy.fake_tool", {}, {
      requestId: "strict-legacy-admin",
      workspaceRoot,
      source: "mcp_sse",
      caller: "admin",
      authHeader: "Bearer admin-token",
      legacyExecute: async () => ({ ok: true }),
    });
    assert.equal(strictLegacyAdmin.ok, false);
    assert.equal(strictLegacyAdmin.code, "UNAUTHORIZED_TOOL");

    const strictListed = await router.listTools({
      requestId: "strict-list",
      workspaceRoot,
      source: "mcp_sse",
      caller: "supervisor",
      authHeader: "Bearer supervisor-token",
      legacyListTools: async () => [{ name: "bridge_health" }],
    });
    assert.equal(strictListed.some((entry) => entry.name === "bridge_health"), false);
  } finally {
    if (typeof previousAdminToken === "undefined") {
      delete process.env.SUPERVISOR_ADMIN_TOKEN;
    } else {
      process.env.SUPERVISOR_ADMIN_TOKEN = previousAdminToken;
    }
  }
});

test("symlink escape is denied by workspace guard", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-router-symlink-outside-"));
  const outsidePath = path.join(outsideRoot, "secret.txt");
  await fs.writeFile(outsidePath, "outside-secret", "utf8");
  const linkPath = path.join(workspaceRoot, "link-outside.txt");
  await fs.symlink(outsidePath, linkPath);

  const result = await router.execute("supervisor.read_file", { path: "link-outside.txt" }, {
    requestId: "symlink-escape",
    workspaceRoot,
    source: "http_api",
    caller: "supervisor",
    authHeader: "Bearer supervisor-token",
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "PATH_OUTSIDE_WORKSPACE");
});

test("rate limit and concurrency protections trigger", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  await fs.writeFile(path.join(workspaceRoot, "inside.txt"), "hello", "utf8");
  const router = makeRouter(workspaceRoot, registryPath, {
    rateLimitWindowMs: 10_000,
    rateLimitMaxRequestsPerWindow: 2,
    maxConcurrentExecutions: 1,
    maxConcurrentExecutionsPerSource: 1,
  });

  const context = {
    requestId: "rate-1",
    workspaceRoot,
    source: "http_api",
    caller: "supervisor",
    authHeader: "Bearer supervisor-token",
  };

  const first = await router.execute("supervisor.read_file", { path: "inside.txt" }, context);
  const second = await router.execute("supervisor.read_file", { path: "inside.txt" }, { ...context, requestId: "rate-2" });
  const third = await router.execute("supervisor.read_file", { path: "inside.txt" }, { ...context, requestId: "rate-3" });

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(third.ok, false);
  assert.equal(third.code, "RATE_LIMIT_EXCEEDED");
});

test("admin role separation is explicit", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const previousAdminToken = process.env.SUPERVISOR_ADMIN_TOKEN;
  process.env.SUPERVISOR_ADMIN_TOKEN = "admin-token";
  try {
    const router = makeRouter(workspaceRoot, registryPath);
    const supervisorTools = await router.listTools({
      requestId: "admin-sep-supervisor",
      workspaceRoot,
      source: "http_api",
      caller: "supervisor",
      authHeader: "Bearer supervisor-token",
    });
    assert.equal(supervisorTools.some((entry) => entry.name === "supervisor.admin_only"), false);

    const adminTools = await router.listTools({
      requestId: "admin-sep-admin",
      workspaceRoot,
      source: "http_api",
      caller: "admin",
      authHeader: "Bearer admin-token",
    });
    assert.equal(adminTools.some((entry) => entry.name === "supervisor.admin_only"), true);
  } finally {
    if (typeof previousAdminToken === "undefined") {
      delete process.env.SUPERVISOR_ADMIN_TOKEN;
    } else {
      process.env.SUPERVISOR_ADMIN_TOKEN = previousAdminToken;
    }
  }
});

test("weak token file permissions warn but do not block execution", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  await fs.writeFile(tokenPath, `${JSON.stringify({ token: "weak-token" }, null, 2)}\n`, { encoding: "utf8", mode: 0o644 });
  await fs.chmod(tokenPath, 0o644);
  await fs.writeFile(path.join(workspaceRoot, "inside.txt"), "weak-perm-ok", "utf8");

  const router = makeRouter(workspaceRoot, registryPath);
  let warningEmitted = false;
  const warningHandler = (warning) => {
    if (warning && warning.code === "TOKEN_FILE_PERMISSIONS_WEAK") {
      warningEmitted = true;
    }
  };
  process.on("warning", warningHandler);

  let result;
  try {
    result = await router.execute("supervisor.read_file", { path: "inside.txt" }, {
      requestId: "perm-check",
      workspaceRoot,
      source: "http_api",
      caller: "token-perm-test",
      authHeader: "Bearer weak-token",
    });
  } finally {
    process.off("warning", warningHandler);
  }

  assert.equal(result.ok, true);
  assert.equal(result.data.content, "weak-perm-ok");
  assert.equal(warningEmitted, true);
});

test("concurrency cap blocks excess execution quickly", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    maxConcurrentExecutions: 1,
    maxConcurrentExecutionsPerSource: 1,
    rateLimitWindowMs: 1_000,
    rateLimitMaxRequestsPerWindow: 1_000,
    supervisorHandlers: {
      "supervisor.read_file": async () => {
        await new Promise((resolve) => setTimeout(resolve, 40));
        return { ok: true };
      },
    },
  });

  const context = {
    workspaceRoot,
    source: "http_api",
    caller: "concurrency-test",
    authHeader: "Bearer supervisor-token",
  };

  const started = Date.now();
  const [first, second, third] = await Promise.all([
    router.execute("supervisor.read_file", { path: "a.txt" }, { ...context, requestId: "conc-1" }),
    router.execute("supervisor.read_file", { path: "a.txt" }, { ...context, requestId: "conc-2" }),
    router.execute("supervisor.read_file", { path: "a.txt" }, { ...context, requestId: "conc-3" }),
  ]);
  const elapsed = Date.now() - started;

  assert.equal(first.ok || second.ok || third.ok, true);
  const blockedCodes = [first, second, third].filter((item) => !item.ok).map((item) => item.code);
  assert.equal(blockedCodes.includes("MAX_CONCURRENT_EXECUTIONS_EXCEEDED") || blockedCodes.includes("SOURCE_CONCURRENCY_LIMIT_EXCEEDED"), true);
  assert.equal(elapsed < 200, true, `concurrency cap should fail excess calls quickly, elapsed=${elapsed}ms`);
});

test("oversized write payload is rejected by schema and runtime limits", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    maxWriteFileBytes: 64,
  });

  const result = await router.execute(
    "supervisor.write_file",
    {
      path: "notes/large.txt",
      content: "x".repeat(80),
    },
    {
      requestId: "oversized-write",
      workspaceRoot,
      source: "http_api",
      caller: "supervisor",
      authHeader: "Bearer supervisor-token",
    },
  );

  assert.equal(result.ok, false);
  assert.equal(result.code === "WRITE_FILE_TOO_LARGE" || result.code === "INVALID_ARGUMENT", true);
});

test("windows absolute path style is rejected on non-windows platforms", async () => {
  if (process.platform === "win32") {
    return;
  }

  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const result = await router.execute("supervisor.read_file", { path: "C:\\Windows\\System32\\drivers\\etc\\hosts" }, {
    requestId: "windows-path",
    workspaceRoot,
    source: "http_api",
    caller: "supervisor",
    authHeader: "Bearer supervisor-token",
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "PATH_OUTSIDE_WORKSPACE");
});

test("nested symlink escape attempt is denied", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const outsideRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-router-nested-symlink-outside-"));
  const outsidePath = path.join(outsideRoot, "secret.txt");
  await fs.writeFile(outsidePath, "outside-secret", "utf8");

  await fs.mkdir(path.join(workspaceRoot, "nested"), { recursive: true });
  const linkDir = path.join(workspaceRoot, "nested", "link");
  await fs.symlink(outsideRoot, linkDir);

  const result = await router.execute("supervisor.read_file", { path: "nested/link/secret.txt" }, {
    requestId: "nested-symlink-escape",
    workspaceRoot,
    source: "http_api",
    caller: "supervisor",
    authHeader: "Bearer supervisor-token",
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "PATH_OUTSIDE_WORKSPACE");
});

test("role resolution is per-request and does not trust replayed invalid tokens", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "supervisor-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const validRole = await router.resolveRole({
    requestId: "role-valid",
    workspaceRoot,
    source: "http_api",
    caller: "role-test",
    authHeader: "Bearer supervisor-token",
  });
  assert.equal(validRole, "supervisor");

  const replayedInvalidRole = await router.resolveRole({
    requestId: "role-invalid",
    workspaceRoot,
    source: "http_api",
    caller: "role-test",
    authHeader: "Bearer supervisor-token-invalid",
  });
  assert.equal(replayedInvalidRole, "anonymous");
});
