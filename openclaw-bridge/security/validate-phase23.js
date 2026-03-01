#!/usr/bin/env node

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execSync } = require("node:child_process");

const {
  computeSecretManifestHash,
  getCanonicalSecretManifest,
} = require("./secret-manifest.js");
const { createSecretAuthority } = require("./secret-authority.js");

function safeExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function hasPattern(filePath, pattern) {
  if (!safeExists(filePath)) {
    return false;
  }
  return pattern.test(fs.readFileSync(filePath, "utf8"));
}

async function verifyScopeAndReuse() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "phase23-validate-"));
  const manifestPath = path.join(tempDir, "secret-manifest.json");
  const manifest = {
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
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  let fetchCount = 0;
  const authority = createSecretAuthority({
    production: true,
    manifestPath,
    expectedHash: computeSecretManifestHash(manifest),
    allowProductionPathOverride: true,
    secretProvider: {
      ping: async () => true,
      fetchSecret: async () => {
        fetchCount += 1;
        return { found: true, value: `value-${fetchCount}` };
      },
    },
  });
  await authority.initialize();

  let scopeEnforced = false;
  try {
    await authority.getExecutionSecrets({
      executionId: "req-1",
      toolSlug: "curl",
      principalId: "bob",
      requestedSecretNames: ["OPENCLAW_API_TOKEN"],
    });
  } catch (error) {
    scopeEnforced = error && error.code === "SECRET_SCOPE_VIOLATION";
  }

  const first = await authority.getExecutionSecrets({
    executionId: "req-2",
    toolSlug: "curl",
    principalId: "alice",
  });
  const second = await authority.getExecutionSecrets({
    executionId: "req-3",
    toolSlug: "curl",
    principalId: "alice",
  });
  const noReuse = first.env.OPENCLAW_API_TOKEN !== second.env.OPENCLAW_API_TOKEN && fetchCount >= 2;

  await authority.close();
  return {
    scopeEnforced,
    noReuse,
  };
}

async function main() {
  const root = path.resolve(__dirname, "..");
  const manifestPath = path.resolve(__dirname, "secret-manifest.json");
  const errors = [];

  const secretManifestPresent =
    safeExists(path.resolve(__dirname, "secret-manifest.js")) &&
    safeExists(path.resolve(__dirname, "secret-authority.js")) &&
    safeExists(path.resolve(__dirname, "verify-secret-manifest.js")) &&
    safeExists(manifestPath);

  let secretManifestHashDeterministic = false;
  let secretRotationSupported = false;
  if (secretManifestPresent) {
    try {
      const manifest = loadJson(manifestPath);
      const hashA = computeSecretManifestHash(manifest);
      const hashB = computeSecretManifestHash(JSON.parse(JSON.stringify(manifest)));
      secretManifestHashDeterministic = hashA === hashB;

      const next = JSON.parse(JSON.stringify(manifest));
      next.secrets[0].secretVersion = Number(next.secrets[0].secretVersion) + 1;
      secretRotationSupported = computeSecretManifestHash(manifest) !== computeSecretManifestHash(next);
      getCanonicalSecretManifest(manifest);
    } catch (error) {
      errors.push(error.message);
    }
  }

  let scopeEnforced = false;
  let noReuse = false;
  try {
    const checks = await verifyScopeAndReuse();
    scopeEnforced = checks.scopeEnforced;
    noReuse = checks.noReuse;
  } catch (error) {
    errors.push(error && error.message ? error.message : String(error));
  }

  const supervisorPath = path.resolve(root, "supervisor", "supervisor-v1.js");
  const baseAdapterPath = path.resolve(root, "tools", "base-adapter.js");
  const secretManagerPath = path.resolve(root, "security", "secret-manager.js");
  const handlersPath = path.resolve(root, "http", "handlers.js");

  const secretInjectionEnvOnly =
    hasPattern(baseAdapterPath, /executionSecretRef/) &&
    hasPattern(baseAdapterPath, /executionSecrets/) &&
    hasPattern(path.resolve(root, "execution", "container-runtime.js"), /Env:/);

  const secretDriftBlocksExecutionInProd =
    hasPattern(supervisorPath, /SECRET_MANIFEST_MISMATCH/) &&
    hasPattern(handlersPath, /secret_manifest_hash/);

  const secretLeakDetectionPresent =
    hasPattern(secretManagerPath, /secret\.leak\.detected/) &&
    hasPattern(secretManagerPath, /encodeURIComponent/) &&
    hasPattern(secretManagerPath, /Buffer\.from/);

  const noGlobalSecretCache = !hasPattern(path.resolve(__dirname, "secret-authority.js"), /globalSecretCache/);

  let noControlPlaneDrift = true;
  try {
    const repoPath = path.resolve(root, "..");
    const diff = execSync(`git -C "${repoPath}" diff --name-only`, { encoding: "utf8" });
    const touched = diff
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (touched.some((file) => file.endsWith("openclaw-bridge/cluster/cluster-manager.js"))) {
      noControlPlaneDrift = false;
    }
  } catch {
    noControlPlaneDrift = false;
  }

  const payload = {
    secret_manifest_present: secretManifestPresent,
    secret_manifest_hash_deterministic: secretManifestHashDeterministic,
    secret_scope_enforced: scopeEnforced,
    secret_injection_env_only: secretInjectionEnvOnly,
    secret_rotation_supported: secretRotationSupported,
    secret_drift_blocks_execution_in_prod: secretDriftBlocksExecutionInProd,
    secret_leak_detection_present: secretLeakDetectionPresent,
    no_global_secret_cache: noGlobalSecretCache,
    no_cross_execution_secret_reuse: noReuse,
    no_control_plane_drift: noControlPlaneDrift,
    errors,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main();
