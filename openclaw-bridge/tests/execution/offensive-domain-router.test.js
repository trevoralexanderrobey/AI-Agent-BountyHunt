const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { createExecutionRouter } = require("../../src/core/execution-router.js");
const { BaseToolAdapter } = require("../../tools/base-adapter.js");

async function makeWorkspace() {
  const workspaceRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "openclaw-phase27-"));
  await fsp.mkdir(path.join(workspaceRoot, ".cline"), { recursive: true });
  await fsp.mkdir(path.join(workspaceRoot, ".openclaw"), { recursive: true });
  return workspaceRoot;
}

async function writeTokenConfig(workspaceRoot, token) {
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  await fsp.mkdir(path.dirname(tokenPath), { recursive: true });
  await fsp.writeFile(tokenPath, `${JSON.stringify({ token }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await fsp.chmod(tokenPath, 0o600);
}

async function makeRegistry(workspaceRoot) {
  const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
  await fsp.mkdir(path.dirname(registryPath), { recursive: true });
  await fsp.writeFile(
    registryPath,
    `${JSON.stringify(
      [
        {
          name: "supervisor.read_file",
          description: "read file",
          inputSchema: {
            type: "object",
            properties: {
              path: { type: "string", minLength: 1 },
            },
            required: ["path"],
            additionalProperties: false,
          },
          mutationClass: "read",
          loggingLevel: "info",
          roles: ["supervisor", "internal", "admin"],
          workspacePathArgs: ["path"],
        },
      ],
      null,
      2,
    )}\n`,
    "utf8",
  );
  return registryPath;
}

function baseContext(workspaceRoot, requestId, extra = {}) {
  return {
    requestId,
    workspaceRoot,
    source: "http_api",
    caller: "phase27-test",
    authHeader: "Bearer phase27-token",
    ...extra,
  };
}

function makeRouter(workspaceRoot, registryPath, overrides = {}) {
  return createExecutionRouter({
    workspaceRoot,
    registryPath,
    auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
    supervisorMode: false,
    supervisorAuthPhase: "compat",
    workloadIntegrityEnabled: false,
    workloadAttestationEnabled: false,
    workloadProvenanceEnabled: false,
    offensiveRateLimitWindowMs: 10_000,
    offensiveMaxPerToolPerWindow: 10,
    offensiveMaxConcurrentOffensive: 10,
    offensiveMaxConcurrentPerTool: 10,
    offensiveBackoffBaseMs: 1000,
    offensiveBackoffMaxMs: 1000,
    ...overrides,
  });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function makeOffensiveMetadataFromProvenance() {
  const provenancePath = path.resolve(__dirname, "../../security/build-provenance.json");
  const provenance = readJson(provenancePath);
  return {
    executionPolicyHash: provenance.executionPolicyHash,
    secretManifestHash: provenance.secretManifestHash,
    workloadManifestHash: provenance.workloadManifestHash,
    offensiveManifestHash: provenance.offensiveManifestHash,
    attestationReferenceHash: provenance.attestationReferenceHash,
  };
}

class DigestMismatchAdapter extends BaseToolAdapter {
  async validateInput() {
    return { valid: true, errors: [] };
  }

  async normalizeOutput(rawOutput) {
    return rawOutput && typeof rawOutput === "object" ? rawOutput : { ok: true };
  }

  async executeContainerImpl(input) {
    const invocation = this.buildContainerInvocation({
      params: input.params,
      timeout: input.timeout,
      requestId: input.requestId,
      inputArtifacts: [],
    });
    invocation.image = "ghcr.io/example/nmap@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    return invocation;
  }
}

test("raw shell-style offensive argument is rejected", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const result = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org;uname -a" },
    baseContext(workspaceRoot, "phase27-shell", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "OFFENSIVE_ARGUMENTS_INVALID");
});

test("unknown offensive execution path is rejected without governed legacy executor", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const result = await router.execute("nmap.run", { target: "scanme.nmap.org" }, baseContext(workspaceRoot, "phase27-unknown"));

  assert.equal(result.ok, false);
  assert.equal(result.code, "UNREGISTERED_OFFENSIVE_TOOL");
});

test("missing required schema arg and unknown flag are rejected", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const missing = await router.execute(
    "nmap.run",
    {},
    baseContext(workspaceRoot, "phase27-missing", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );
  assert.equal(missing.ok, false);
  assert.equal(missing.code, "OFFENSIVE_ARGUMENTS_INVALID");

  const unknownFlag = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org", flags: ["--no-such-flag"] },
    baseContext(workspaceRoot, "phase27-unknown-flag", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );
  assert.equal(unknownFlag.ok, false);
  assert.equal(unknownFlag.code, "OFFENSIVE_ARGUMENTS_INVALID");
});

test("offensive domain is fail-closed on manifest trust failure", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    offensiveExpectedHash: "0".repeat(64),
  });

  const result = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org" },
    baseContext(workspaceRoot, "phase27-domain-untrusted", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "OFFENSIVE_DOMAIN_NOT_TRUSTED");
});

test("non-interactive mode is enforced and network policy violations are blocked", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const interactive = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org", tty: true },
    baseContext(workspaceRoot, "phase27-tty", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );
  assert.equal(interactive.ok, false);
  assert.equal(interactive.code, "OFFENSIVE_ARGUMENTS_INVALID");

  const localhost = await router.execute(
    "nmap.run",
    { target: "localhost" },
    baseContext(workspaceRoot, "phase27-localhost", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );
  assert.equal(localhost.ok, false);
  assert.equal(localhost.code, "OFFENSIVE_TARGET_INVALID");

  const protocol = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org", protocol: "http" },
    baseContext(workspaceRoot, "phase27-protocol", {
      legacyExecute: async () => ({ ok: true }),
    }),
  );
  assert.equal(protocol.ok, false);
  assert.equal(
    protocol.code === "OFFENSIVE_PROTOCOL_NOT_ALLOWED" || protocol.code === "OFFENSIVE_ARGUMENTS_INVALID",
    true,
  );
});

test("offensive rate limit and backoff are enforced", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    offensiveRateLimitWindowMs: 60_000,
    offensiveMaxPerToolPerWindow: 1,
    offensiveBackoffBaseMs: 10_000,
    offensiveBackoffMaxMs: 10_000,
  });

  const context = baseContext(workspaceRoot, "phase27-rate-1", {
    legacyExecute: async () => ({ ok: true }),
  });

  const first = await router.execute("nmap.run", { target: "scanme.nmap.org" }, context);
  const second = await router.execute("nmap.run", { target: "scanme.nmap.org" }, { ...context, requestId: "phase27-rate-2" });
  const third = await router.execute("nmap.run", { target: "scanme.nmap.org" }, { ...context, requestId: "phase27-rate-3" });

  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.equal(second.code, "OFFENSIVE_RATE_LIMIT_EXCEEDED");
  assert.equal(third.ok, false);
  assert.equal(third.code, "OFFENSIVE_BACKOFF_ACTIVE");
});

test("offensive global concurrency cap is enforced", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath, {
    offensiveMaxPerToolPerWindow: 10,
    offensiveMaxConcurrentOffensive: 1,
    offensiveMaxConcurrentPerTool: 1,
    offensiveBackoffBaseMs: 10_000,
    offensiveBackoffMaxMs: 10_000,
  });

  const legacyExecute = async () => {
    await new Promise((resolve) => setTimeout(resolve, 40));
    return { ok: true };
  };

  const [a, b] = await Promise.all([
    router.execute("nmap.run", { target: "scanme.nmap.org" }, baseContext(workspaceRoot, "phase27-concurrency-a", { legacyExecute })),
    router.execute(
      "sqlmap.run",
      { url: "https://example.com/?id=1", method: "GET", flags: ["--batch"] },
      baseContext(workspaceRoot, "phase27-concurrency-b", { legacyExecute }),
    ),
  ]);

  const blocked = [a, b].filter((entry) => entry.ok === false).map((entry) => entry.code);
  assert.equal(blocked.length >= 1, true);
  assert.equal(blocked.includes("OFFENSIVE_CONCURRENCY_EXCEEDED") || blocked.includes("OFFENSIVE_BACKOFF_ACTIVE"), true);
});

test("provenance invalid request is rejected with valid attestation metadata present", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");

  const reference = readJson(path.resolve(__dirname, "../../security/workload-attestation-reference.json"));
  const provenancePath = path.resolve(__dirname, "../../security/build-provenance.json");
  const provenanceHashPath = path.resolve(__dirname, "../../security/build-provenance.hash");
  const provenancePublicKeyPath = path.resolve(__dirname, "../../security/build-provenance.pub");

  const tamperRoot = await fsp.mkdtemp(path.join(os.tmpdir(), "phase27-provenance-invalid-"));
  const tamperedProvenancePath = path.join(tamperRoot, "build-provenance.json");
  const tamperedHashPath = path.join(tamperRoot, "build-provenance.hash");
  const tamperedPublicKeyPath = path.join(tamperRoot, "build-provenance.pub");

  const tampered = readJson(provenancePath);
  tampered.repository = "https://example.com/tampered-phase27.git";
  await fsp.writeFile(tamperedProvenancePath, `${JSON.stringify(tampered, null, 2)}\n`, "utf8");
  await fsp.copyFile(provenanceHashPath, tamperedHashPath);
  await fsp.copyFile(provenancePublicKeyPath, tamperedPublicKeyPath);

  let legacyCalled = false;
  const router = makeRouter(workspaceRoot, registryPath, {
    workloadAttestationEnabled: true,
    workloadProvenanceEnabled: true,
    buildProvenancePath: tamperedProvenancePath,
    buildProvenanceHashPath: tamperedHashPath,
    buildProvenancePublicKeyPath: tamperedPublicKeyPath,
  });

  const result = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org" },
    baseContext(workspaceRoot, "phase27-provenance-invalid", {
      transportMetadata: {
        containerImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        executionMetadata: {
          executionPolicyHash: reference.executionPolicyHash,
          secretManifestHash: reference.secretManifestHash,
          workloadManifestHash: reference.workloadManifestHash,
          offensiveManifestHash: reference.offensiveManifestHash,
          attestationReferenceHash: readJson(path.resolve(__dirname, "../../security/build-provenance.json")).attestationReferenceHash,
        },
      },
      legacyExecute: async () => {
        legacyCalled = true;
        return { ok: true };
      },
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_PROVENANCE_NOT_TRUSTED");
  assert.equal(legacyCalled, false);
});

test("provenance-valid request is still rejected if isolation enforcement fails", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const provenance = readJson(path.resolve(__dirname, "../../security/build-provenance.json"));

  const router = makeRouter(workspaceRoot, registryPath, {
    workloadProvenanceEnabled: true,
  });

  const result = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org" },
    baseContext(workspaceRoot, "phase27-isolation-invalid", {
      transportMetadata: {
        containerImageDigest: provenance.containerImageDigests["nmap.run"] || provenance.containerImageDigests.nmap,
        executionMetadata: makeOffensiveMetadataFromProvenance(),
      },
      legacyExecute: async () => {
        const err = new Error("isolation invalid");
        err.code = "WORKLOAD_ISOLATION_INVALID";
        throw err;
      },
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_ISOLATION_INVALID");
});

test("command timeout is surfaced for offensive execution", async () => {
  const workspaceRoot = await makeWorkspace();
  const registryPath = await makeRegistry(workspaceRoot);
  await writeTokenConfig(workspaceRoot, "phase27-token");
  const router = makeRouter(workspaceRoot, registryPath);

  const result = await router.execute(
    "nmap.run",
    { target: "scanme.nmap.org" },
    baseContext(workspaceRoot, "phase27-timeout", {
      legacyExecute: async () => {
        const err = new Error("timeout");
        err.code = "COMMAND_TIMEOUT";
        throw err;
      },
    }),
  );

  assert.equal(result.ok, false);
  assert.equal(result.code, "COMMAND_TIMEOUT");
});

test("container digest mismatch is rejected by deterministic offensive isolation enforcement", async () => {
  const runtime = {
    async runContainer() {
      return { ok: true };
    },
  };

  const adapter = new DigestMismatchAdapter({
    name: "Nmap",
    slug: "nmap",
    executionMode: "container",
    containerRuntimeEnabled: true,
    containerRuntime: runtime,
    resourcePolicies: {
      nmap: {
        cpuShares: 1024,
        memoryLimitMb: 1024,
        maxRuntimeSeconds: 300,
        maxOutputBytes: 5 * 1024 * 1024,
      },
    },
  });

  const offensivePlan = {
    toolName: "nmap",
    toolVersion: "7.94",
    workloadID: "nmap",
    containerImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    offensiveManifestHash: "f".repeat(64),
    isolationProfile: {
      runAsNonRoot: true,
      dropCapabilities: ["ALL"],
      privileged: false,
      hostPID: false,
      hostNetwork: false,
      hostMounts: false,
      readOnlyRootFilesystem: true,
      writableVolumes: ["scratch"],
      seccompProfile: "runtime/default",
      appArmorProfile: "openclaw-default",
      tty: false,
      stdin: false,
    },
    isolationProfileHash: "e".repeat(64),
    runtimeConfigHash: "d".repeat(64),
    nonInteractive: true,
    resourceLimits: {
      cpuShares: 256,
      memoryLimitMb: 256,
      maxRuntimeSeconds: 60,
      maxOutputBytes: 1024 * 1024,
    },
    executionConstraints: {
      networkScope: "target-bound",
      requiresTarget: true,
      allowedProtocols: ["tcp"],
      maxRuntimeSeconds: 60,
      allowPrivateTargets: false,
      allowCidrs: false,
      singleTarget: true,
      maxThreads: 4,
    },
    forcedFlags: [],
    allowedFlags: [],
    deniedFlags: [],
    args: { target: "scanme.nmap.org" },
    target: "scanme.nmap.org",
    protocol: "tcp",
  };

  const result = await adapter.execute({
    params: { target: "scanme.nmap.org" },
    timeout: 1000,
    requestId: "phase27-digest-mismatch",
    offensiveExecutionPlan: offensivePlan,
    resourceLimits: offensivePlan.resourceLimits,
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "WORKLOAD_ISOLATION_INVALID");
});
