const test = require("node:test");
const assert = require("node:assert/strict");

const {
  validateSecretSchema,
  getCanonicalSecretManifest,
  computeSecretManifestHash,
} = require("../../security/secret-manifest.js");

function baseManifest(overrides = {}) {
  return {
    secrets: [
      {
        secretName: "OPENCLAW_API_TOKEN",
        allowedTools: ["curl"],
        allowedPrincipals: "*",
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
}

test("secret manifest canonicalization and hash are deterministic", () => {
  const manifest = baseManifest();
  const canonicalA = JSON.stringify(getCanonicalSecretManifest(manifest));
  const canonicalB = JSON.stringify(getCanonicalSecretManifest(JSON.parse(canonicalA)));
  const hashA = computeSecretManifestHash(manifest);
  const hashB = computeSecretManifestHash(JSON.parse(canonicalA));

  assert.equal(canonicalA, canonicalB);
  assert.equal(hashA, hashB);
});

test("secret manifest hash changes when metadata changes", () => {
  const a = baseManifest();
  const b = baseManifest({
    secrets: [
      {
        ...baseManifest().secrets[0],
        allowedTools: ["curl", "nmap"],
      },
    ],
  });
  assert.notEqual(computeSecretManifestHash(a), computeSecretManifestHash(b));
});

test("secret manifest schema rejects missing required fields", () => {
  const manifest = baseManifest();
  delete manifest.secrets[0].injectionMode;
  const validation = validateSecretSchema(manifest);
  assert.equal(validation.valid, false);
  assert.equal(validation.errors.some((item) => item.includes("injectionMode")), true);
});
