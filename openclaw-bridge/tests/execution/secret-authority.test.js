const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");

const { computeSecretManifestHash } = require("../../security/secret-manifest.js");
const { createSecretAuthority } = require("../../security/secret-authority.js");

function writeManifest(dirPath, overrides = {}) {
  const manifest = {
    secrets: [
      {
        secretName: "OPENCLAW_API_TOKEN",
        allowedTools: ["curl"],
        allowedPrincipals: ["alice"],
        rotationPolicy: {
          cadence: "30d",
          provider: "external-store",
        },
        secretVersion: 1,
        injectionMode: "env-only",
        productionRequired: true,
      },
    ],
    ...overrides,
  };
  const manifestPath = path.join(dirPath, "secret-manifest.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return {
    manifestPath,
    manifest,
  };
}

test("secret authority enforces tool and principal scope", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-authority-test-"));
  const { manifestPath, manifest } = writeManifest(tempDir);

  const provider = {
    ping: async () => true,
    fetchSecret: async () => ({ found: true, value: "secret-for-alice" }),
  };

  const authority = createSecretAuthority({
    production: true,
    manifestPath,
    expectedHash: computeSecretManifestHash(manifest),
    allowProductionPathOverride: true,
    secretProvider: provider,
  });

  await authority.initialize();
  const allowed = await authority.getExecutionSecrets({
    executionId: "req-1",
    toolSlug: "curl",
    principalId: "alice",
  });
  assert.equal(typeof allowed.env.OPENCLAW_API_TOKEN, "string");

  await assert.rejects(
    authority.getExecutionSecrets({
      executionId: "req-2",
      toolSlug: "curl",
      principalId: "bob",
      requestedSecretNames: ["OPENCLAW_API_TOKEN"],
    }),
    (error) => {
      assert.equal(error.code, "SECRET_SCOPE_VIOLATION");
      return true;
    },
  );
});

test("production secret store connectivity failure blocks initialization", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-authority-test-"));
  const { manifestPath, manifest } = writeManifest(tempDir);

  const authority = createSecretAuthority({
    production: true,
    manifestPath,
    expectedHash: computeSecretManifestHash(manifest),
    allowProductionPathOverride: true,
    provider: "none",
  });

  await assert.rejects(
    authority.initialize(),
    (error) => {
      assert.equal(error.code, "SECRET_STORE_UNREACHABLE");
      return true;
    },
  );
});

test("secret authority does not cache values across executions", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-authority-test-"));
  const { manifestPath, manifest } = writeManifest(tempDir);
  let fetchCount = 0;

  const provider = {
    ping: async () => true,
    fetchSecret: async () => {
      fetchCount += 1;
      return { found: true, value: `secret-${fetchCount}` };
    },
  };

  const authority = createSecretAuthority({
    production: true,
    manifestPath,
    expectedHash: computeSecretManifestHash(manifest),
    allowProductionPathOverride: true,
    secretProvider: provider,
  });
  await authority.initialize();

  const first = await authority.getExecutionSecrets({
    executionId: "exec-1",
    toolSlug: "curl",
    principalId: "alice",
  });
  const second = await authority.getExecutionSecrets({
    executionId: "exec-2",
    toolSlug: "curl",
    principalId: "alice",
  });

  assert.equal(first.env.OPENCLAW_API_TOKEN, "secret-1");
  assert.equal(second.env.OPENCLAW_API_TOKEN, "secret-2");
  assert.equal(fetchCount, 2);
});

test("rotation applies to new executions without mutating running execution snapshot", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-authority-test-"));
  const firstManifest = writeManifest(tempDir, {
    secrets: [
      {
        secretName: "OPENCLAW_API_TOKEN",
        allowedTools: ["curl"],
        allowedPrincipals: ["alice"],
        rotationPolicy: { cadence: "30d", provider: "external-store" },
        secretVersion: 1,
        injectionMode: "env-only",
        productionRequired: true,
      },
    ],
  });

  const provider = {
    ping: async () => true,
    fetchSecret: async (input) => ({ found: true, value: `value-v${input.secretVersion}` }),
  };

  const authority = createSecretAuthority({
    production: true,
    manifestPath: firstManifest.manifestPath,
    expectedHash: computeSecretManifestHash(firstManifest.manifest),
    allowProductionPathOverride: true,
    secretProvider: provider,
  });
  await authority.initialize();

  const running = await authority.getExecutionSecrets({
    executionId: "run-1",
    toolSlug: "curl",
    principalId: "alice",
  });
  assert.equal(running.env.OPENCLAW_API_TOKEN, "value-v1");

  const secondManifest = writeManifest(tempDir, {
    secrets: [
      {
        secretName: "OPENCLAW_API_TOKEN",
        allowedTools: ["curl"],
        allowedPrincipals: ["alice"],
        rotationPolicy: { cadence: "30d", provider: "external-store" },
        secretVersion: 2,
        injectionMode: "env-only",
        productionRequired: true,
      },
    ],
  });

  const rotatedAuthority = createSecretAuthority({
    production: true,
    manifestPath: secondManifest.manifestPath,
    expectedHash: computeSecretManifestHash(secondManifest.manifest),
    allowProductionPathOverride: true,
    secretProvider: provider,
  });
  await rotatedAuthority.initialize();

  const next = await rotatedAuthority.getExecutionSecrets({
    executionId: "run-2",
    toolSlug: "curl",
    principalId: "alice",
  });

  assert.equal(running.env.OPENCLAW_API_TOKEN, "value-v1");
  assert.equal(next.env.OPENCLAW_API_TOKEN, "value-v2");
});

test("production peer secret manifest hash mismatch is classified as blocking", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-authority-test-"));
  const { manifestPath, manifest } = writeManifest(tempDir);
  const authority = createSecretAuthority({
    production: true,
    manifestPath,
    expectedHash: computeSecretManifestHash(manifest),
    allowProductionPathOverride: true,
    secretProvider: {
      ping: async () => true,
      fetchSecret: async () => ({ found: true, value: "secret" }),
    },
  });
  await authority.initialize();

  const summary = authority.evaluatePeerSecretPosture([
    {
      peerId: "node-b",
      status: "UP",
      secretManifestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  ]);
  assert.equal(summary.ok, false);
  assert.equal(summary.criticalMismatches.some((entry) => entry.classification === "SECRET_MANIFEST_MISMATCH"), true);
});
