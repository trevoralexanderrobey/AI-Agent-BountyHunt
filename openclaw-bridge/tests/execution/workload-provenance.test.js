const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  createWorkloadProvenanceRuntime,
  computeDetachedProvenancePayloadBytes,
  getCanonicalBuildProvenance,
  loadBuildProvenanceFromDisk,
} = require("../../security/workload-provenance.js");

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function makeFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-phase26-provenance-"));
  const securityDir = path.join(root, "security");
  fs.mkdirSync(securityDir, { recursive: true });

  const lockPath = path.join(root, "package-lock.json");
  fs.writeFileSync(lockPath, JSON.stringify({ name: "phase26", lockfileVersion: 3 }, null, 2), "utf8");

  const keyPair = crypto.generateKeyPairSync("ed25519");
  const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString("utf8");
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString("utf8");

  const base = {
    provenanceVersion: 1,
    gitCommitSha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    repository: "https://example.com/openclaw.git",
    buildTimestamp: new Date("2026-03-02T00:00:00.000Z").toISOString(),
    workloadManifestHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    executionPolicyHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    secretManifestHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    attestationReferenceHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    containerImageDigests: {
      "supervisor.read_file": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    dependencyLockHash: sha256File(lockPath),
    nodeVersion: process.version,
    buildEnvironmentFingerprint: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    signatureAlgorithm: "ed25519",
  };

  const canonicalForSigning = getCanonicalBuildProvenance({
    ...base,
    provenanceSignature: "cGxhY2Vob2xkZXI=",
    provenanceHash: "0".repeat(64),
  });

  const payloadBytes = computeDetachedProvenancePayloadBytes(canonicalForSigning);
  const payloadHash = crypto.createHash("sha256").update(payloadBytes).digest("hex");
  const signature = crypto.sign(null, payloadBytes, crypto.createPrivateKey(privateKeyPem)).toString("base64");

  const document = getCanonicalBuildProvenance({
    ...base,
    provenanceSignature: signature,
    provenanceHash: payloadHash,
  });

  const provenancePath = path.join(securityDir, "build-provenance.json");
  const hashPath = path.join(securityDir, "build-provenance.hash");
  const publicKeyPath = path.join(securityDir, "build-provenance.pub");

  fs.writeFileSync(provenancePath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  fs.writeFileSync(hashPath, `${payloadHash}\n`, "utf8");
  fs.writeFileSync(publicKeyPath, publicKeyPem, "utf8");
  fs.chmodSync(provenancePath, 0o444);
  fs.chmodSync(hashPath, 0o444);
  fs.chmodSync(publicKeyPath, 0o444);

  return {
    root,
    securityDir,
    lockPath,
    privateKeyPem,
    publicKeyPem,
    provenancePath,
    hashPath,
    publicKeyPath,
    document,
    payloadBytes,
    payloadHash,
  };
}

test("valid detached payload signature verifies", () => {
  const fixture = makeFixture();

  const loaded = loadBuildProvenanceFromDisk({
    production: false,
    provenancePath: fixture.provenancePath,
    provenanceHashPath: fixture.hashPath,
    publicKeyPath: fixture.publicKeyPath,
    dependencyLockPath: fixture.lockPath,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });

  assert.equal(loaded.canonicalPayloadHash, fixture.payloadHash);
  assert.equal(loaded.provenance.gitCommitSha, fixture.document.gitCommitSha);
});

test("signature over payload hash is rejected", () => {
  const fixture = makeFixture();
  const tamperedDoc = JSON.parse(fs.readFileSync(fixture.provenancePath, "utf8"));
  tamperedDoc.provenanceSignature = crypto
    .sign(null, Buffer.from(tamperedDoc.provenanceHash, "utf8"), crypto.createPrivateKey(fixture.privateKeyPem))
    .toString("base64");
  fs.chmodSync(fixture.provenancePath, 0o644);
  fs.writeFileSync(fixture.provenancePath, `${JSON.stringify(tamperedDoc, null, 2)}\n`, "utf8");
  fs.chmodSync(fixture.provenancePath, 0o444);

  assert.throws(() => {
    loadBuildProvenanceFromDisk({
      production: false,
      provenancePath: fixture.provenancePath,
      provenanceHashPath: fixture.hashPath,
      publicKeyPath: fixture.publicKeyPath,
      dependencyLockPath: fixture.lockPath,
      allowProductionPathOverride: true,
      productionContainerMode: false,
    });
  }, (error) => error && error.code === "WORKLOAD_PROVENANCE_SIGNATURE_INVALID");
});

test("tampered payload with unchanged signature is rejected", () => {
  const fixture = makeFixture();
  const tamperedDoc = JSON.parse(fs.readFileSync(fixture.provenancePath, "utf8"));
  tamperedDoc.repository = "https://example.com/tampered.git";
  fs.chmodSync(fixture.provenancePath, 0o644);
  fs.writeFileSync(fixture.provenancePath, `${JSON.stringify(tamperedDoc, null, 2)}\n`, "utf8");
  fs.chmodSync(fixture.provenancePath, 0o444);

  assert.throws(() => {
    loadBuildProvenanceFromDisk({
      production: false,
      provenancePath: fixture.provenancePath,
      provenanceHashPath: fixture.hashPath,
      publicKeyPath: fixture.publicKeyPath,
      dependencyLockPath: fixture.lockPath,
      allowProductionPathOverride: true,
      productionContainerMode: false,
    });
  }, (error) => error && error.code === "WORKLOAD_PROVENANCE_HASH_MISMATCH");
});

test("production forbids env inline public key overrides", () => {
  const fixture = makeFixture();

  const previousInline = process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY;
  process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY = fixture.publicKeyPem;

  try {
    assert.throws(() => {
      loadBuildProvenanceFromDisk({
        production: true,
        provenancePath: fs.realpathSync(fixture.provenancePath),
        provenanceHashPath: fs.realpathSync(fixture.hashPath),
        publicKeyPath: fs.realpathSync(fixture.publicKeyPath),
        dependencyLockPath: fixture.lockPath,
        allowProductionPathOverride: true,
        productionContainerMode: false,
      });
    }, (error) => error && error.code === "WORKLOAD_PROVENANCE_KEY_OVERRIDE_FORBIDDEN");
  } finally {
    if (typeof previousInline === "undefined") {
      delete process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY;
    } else {
      process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY = previousInline;
    }
  }
});

test("single-flight ttl reverify runs once under concurrency", async () => {
  const fixture = makeFixture();
  const events = [];

  const runtime = createWorkloadProvenanceRuntime({
    production: false,
    provenancePath: fixture.provenancePath,
    provenanceHashPath: fixture.hashPath,
    publicKeyPath: fixture.publicKeyPath,
    dependencyLockPath: fixture.lockPath,
    allowProductionPathOverride: true,
    productionContainerMode: false,
    reverifyTtlMs: 1,
    auditLog: (event) => events.push(event),
  });

  const startup = runtime.initializeProvenance();
  assert.equal(startup.ok, true);

  await new Promise((resolve) => setTimeout(resolve, 10));

  const promises = [];
  for (let index = 0; index < 100; index += 1) {
    promises.push(
      runtime.verifyExecution({
        workloadID: "supervisor.read_file",
        runtimeDigest: fixture.document.containerImageDigests["supervisor.read_file"],
        localMetadata: {
          executionPolicyHash: fixture.document.executionPolicyHash,
          secretManifestHash: fixture.document.secretManifestHash,
          workloadManifestHash: fixture.document.workloadManifestHash,
          attestationReferenceHash: fixture.document.attestationReferenceHash,
        },
      }),
    );
  }

  const results = await Promise.all(promises);
  assert.equal(results.every((entry) => entry.ok === true), true);

  const ttlReverifyEvents = events.filter(
    (event) =>
      event &&
      event.status === "ok" &&
      event.details &&
      typeof event.details === "object" &&
      event.details.reason === "ttl_reverify",
  );

  assert.equal(ttlReverifyEvents.length, 1);
});

test("snapshot mismatch makes local node untrusted", async () => {
  const fixture = makeFixture();

  const runtime = createWorkloadProvenanceRuntime({
    production: false,
    provenancePath: fixture.provenancePath,
    provenanceHashPath: fixture.hashPath,
    publicKeyPath: fixture.publicKeyPath,
    dependencyLockPath: fixture.lockPath,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });

  assert.equal(runtime.initializeProvenance().ok, true);

  const mismatch = await runtime.verifyExecution({
    workloadID: "supervisor.read_file",
    runtimeDigest: fixture.document.containerImageDigests["supervisor.read_file"],
    localMetadata: {
      executionPolicyHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      secretManifestHash: fixture.document.secretManifestHash,
      workloadManifestHash: fixture.document.workloadManifestHash,
      attestationReferenceHash: fixture.document.attestationReferenceHash,
    },
  });

  assert.equal(mismatch.ok, false);
  assert.equal(mismatch.code, "WORKLOAD_PROVENANCE_NOT_TRUSTED");

  const subsequent = await runtime.verifyExecution({
    workloadID: "supervisor.read_file",
    runtimeDigest: fixture.document.containerImageDigests["supervisor.read_file"],
    localMetadata: {
      executionPolicyHash: fixture.document.executionPolicyHash,
      secretManifestHash: fixture.document.secretManifestHash,
      workloadManifestHash: fixture.document.workloadManifestHash,
      attestationReferenceHash: fixture.document.attestationReferenceHash,
    },
  });

  assert.equal(subsequent.ok, false);
  assert.equal(subsequent.code, "WORKLOAD_PROVENANCE_NOT_TRUSTED");
});

test("production rejects symlinked provenance path segments", () => {
  const fixture = makeFixture();
  const symlinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-phase26-symlink-"));
  const symlinkPath = path.join(symlinkRoot, "build-provenance.json");
  fs.symlinkSync(fixture.provenancePath, symlinkPath);

  assert.throws(() => {
    loadBuildProvenanceFromDisk({
      production: true,
      provenancePath: symlinkPath,
      provenanceHashPath: fixture.hashPath,
      publicKeyPath: fixture.publicKeyPath,
      dependencyLockPath: fixture.lockPath,
      allowProductionPathOverride: true,
      productionContainerMode: false,
    });
  }, (error) => error && error.code === "WORKLOAD_PROVENANCE_SYMLINK_FORBIDDEN");
});
