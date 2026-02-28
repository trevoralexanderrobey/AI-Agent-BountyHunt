#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const {
  validatePolicySchema,
  serializeCanonical,
  computePolicyHash,
} = require("./execution-policy-manifest.js");
const { verifyPolicySignature } = require("./policy-authority.js");

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  return fallback;
}

function parseArgs(argv) {
  const args = Array.isArray(argv) ? argv.slice(2) : [];
  const parsed = {
    manifestPath: path.resolve(__dirname, "execution-policy.json"),
    signaturePath: path.resolve(__dirname, "execution-policy.json.sig"),
    publicKeyPath: path.resolve(__dirname, "execution-policy.pub.pem"),
    previousManifestPath: "",
    production: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--manifest") {
      parsed.manifestPath = path.resolve(String(args[index + 1] || ""));
      index += 1;
      continue;
    }
    if (token === "--signature") {
      parsed.signaturePath = path.resolve(String(args[index + 1] || ""));
      index += 1;
      continue;
    }
    if (token === "--public-key") {
      parsed.publicKeyPath = path.resolve(String(args[index + 1] || ""));
      index += 1;
      continue;
    }
    if (token === "--previous-manifest") {
      parsed.previousManifestPath = path.resolve(String(args[index + 1] || ""));
      index += 1;
      continue;
    }
    if (token === "--production") {
      parsed.production = parseBoolean(args[index + 1], false);
      index += 1;
      continue;
    }
  }

  return parsed;
}

function fail(code, message, details = {}) {
  const payload = {
    ok: false,
    code,
    message,
    details,
  };
  process.stderr.write(`${JSON.stringify(payload)}\n`);
  process.exit(1);
}

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function main() {
  const args = parseArgs(process.argv);

  if (!fs.existsSync(args.manifestPath)) {
    fail("POLICY_FILE_NOT_PRESENT", "Policy manifest file is missing", {
      manifestPath: args.manifestPath,
    });
  }

  const policy = readJson(args.manifestPath);
  const validation = validatePolicySchema(policy);
  if (!validation.valid) {
    fail("POLICY_SCHEMA_INVALID", "Policy schema validation failed", {
      errors: validation.errors,
    });
  }

  const canonicalA = serializeCanonical(policy);
  const canonicalB = serializeCanonical(JSON.parse(canonicalA));
  if (canonicalA !== canonicalB) {
    fail("POLICY_CANONICAL_NON_DETERMINISTIC", "Canonical serialization is non-deterministic");
  }

  const hash = computePolicyHash(policy);

  if (args.production) {
    if (!fs.existsSync(args.signaturePath)) {
      fail("POLICY_SIGNATURE_INVALID", "Policy signature file is missing", {
        signaturePath: args.signaturePath,
      });
    }

    if (!fs.existsSync(args.publicKeyPath)) {
      fail("POLICY_SIGNATURE_INVALID", "Policy public key file is missing", {
        publicKeyPath: args.publicKeyPath,
      });
    }

    const verifyResult = verifyPolicySignature({
      canonicalJson: canonicalA,
      signaturePath: args.signaturePath,
      publicKeyPath: args.publicKeyPath,
    });
    if (!verifyResult.ok) {
      fail(
        normalizeString(verifyResult.code) || "POLICY_SIGNATURE_INVALID",
        normalizeString(verifyResult.message) || "Policy signature verification failed",
        verifyResult.details || {},
      );
    }
  }

  if (args.previousManifestPath && fs.existsSync(args.previousManifestPath)) {
    const previousPolicy = readJson(args.previousManifestPath);
    const previousHash = computePolicyHash(previousPolicy);
    const previousVersion = Number(previousPolicy && previousPolicy.policyVersion);
    const currentVersion = Number(policy && policy.policyVersion);

    if (previousHash !== hash && currentVersion <= previousVersion) {
      fail("POLICY_VERSION_BUMP_REQUIRED", "policyVersion must increment when policy hash changes", {
        previousVersion,
        currentVersion,
      });
    }
  }

  const payload = {
    ok: true,
    policy_hash: hash,
    policy_version: policy.policyVersion,
  };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

main();
