const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  computeAttestationReferenceHash,
  initializeAttestation,
  verifyAttestationEvidence,
} = require("../../security/workload-attestation.js");

function createReferenceFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-attestation-ref-"));
  const referencePath = path.join(root, "workload-attestation-reference.json");
  const reference = {
    referenceVersion: 1,
    executionPolicyHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    secretManifestHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    workloadManifestHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    offensiveManifestHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    evidenceTtlMs: 120000,
  };
  fs.writeFileSync(referencePath, `${JSON.stringify(reference, null, 2)}\n`, "utf8");
  return {
    root,
    referencePath,
    reference,
    expectedHash: computeAttestationReferenceHash(reference),
    localMetadata: {
      executionPolicyHash: reference.executionPolicyHash,
      secretManifestHash: reference.secretManifestHash,
      workloadManifestHash: reference.workloadManifestHash,
      offensiveManifestHash: reference.offensiveManifestHash,
    },
  };
}

test("deterministic evidence generation for fixed challenge input", () => {
  const fixture = createReferenceFixture();
  const runtime = initializeAttestation({
    production: false,
    referencePath: fixture.referencePath,
    expectedReferenceHash: fixture.expectedHash,
    localMetadataProvider: () => fixture.localMetadata,
  });
  assert.equal(runtime.initializeAttestation().ok, true);

  const challenge = {
    nonce: "phase25-deterministic-nonce",
    timestampMs: 1760000000000,
  };
  const first = runtime.generateAttestationEvidence(challenge, {
    localMetadata: fixture.localMetadata,
    runtimeMeasurements: { source: "test" },
  });
  const second = runtime.generateAttestationEvidence(challenge, {
    localMetadata: fixture.localMetadata,
    runtimeMeasurements: { source: "test" },
  });

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(first.evidence.evidenceHash, second.evidence.evidenceHash);
  assert.equal(first.evidence.signature, second.evidence.signature);
});

test("signature verification succeeds for generated evidence", () => {
  const fixture = createReferenceFixture();
  const runtime = initializeAttestation({
    production: false,
    referencePath: fixture.referencePath,
    expectedReferenceHash: fixture.expectedHash,
    localMetadataProvider: () => fixture.localMetadata,
  });
  assert.equal(runtime.initializeAttestation().ok, true);

  const challenge = {
    nonce: "phase25-verify-nonce",
    timestampMs: Date.now(),
  };
  const generated = runtime.generateAttestationEvidence(challenge, {
    localMetadata: fixture.localMetadata,
    runtimeMeasurements: { source: "verify" },
  });
  assert.equal(generated.ok, true);

  const verified = verifyAttestationEvidence(generated.evidence, fixture.reference, {
    challenge,
    replayCache: new Map(),
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.code, "WORKLOAD_ATTESTATION_VERIFIED");
});

test("nonce replay is rejected", () => {
  const fixture = createReferenceFixture();
  const runtime = initializeAttestation({
    production: false,
    referencePath: fixture.referencePath,
    expectedReferenceHash: fixture.expectedHash,
    localMetadataProvider: () => fixture.localMetadata,
  });
  assert.equal(runtime.initializeAttestation().ok, true);

  const challenge = {
    nonce: "phase25-replay-nonce",
    timestampMs: Date.now(),
  };
  const generated = runtime.generateAttestationEvidence(challenge, {
    localMetadata: fixture.localMetadata,
    runtimeMeasurements: { source: "replay" },
  });

  const replayCache = new Map();
  const first = verifyAttestationEvidence(generated.evidence, fixture.reference, {
    challenge,
    replayCache,
  });
  const replay = verifyAttestationEvidence(generated.evidence, fixture.reference, {
    challenge,
    replayCache,
  });

  assert.equal(first.ok, true);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "WORKLOAD_ATTESTATION_REPLAY_DETECTED");
});

test("expired evidence is rejected", () => {
  const fixture = createReferenceFixture();
  const runtime = initializeAttestation({
    production: false,
    referencePath: fixture.referencePath,
    expectedReferenceHash: fixture.expectedHash,
    localMetadataProvider: () => fixture.localMetadata,
  });
  assert.equal(runtime.initializeAttestation().ok, true);

  const challenge = {
    nonce: "phase25-expired-nonce",
    timestampMs: Date.now(),
  };
  const generated = runtime.generateAttestationEvidence(challenge, {
    localMetadata: fixture.localMetadata,
    runtimeMeasurements: { source: "expired" },
  });

  const result = verifyAttestationEvidence(generated.evidence, fixture.reference, {
    challenge,
    nowMs: generated.evidence.expiresAtMs + 1,
    replayCache: new Map(),
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_ATTESTATION_STALE");
});
