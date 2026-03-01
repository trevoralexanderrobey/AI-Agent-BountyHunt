#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const {
  validateSecretSchema,
  getCanonicalSecretManifest,
  computeSecretManifestHash,
} = require("./secret-manifest.js");

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
    manifestPath: path.resolve(__dirname, "secret-manifest.json"),
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

function hasSuspiciousSecretPatterns(rawContents) {
  const patterns = [
    /BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY/,
    /AKIA[0-9A-Z]{16}/,
    /gh[pousr]_[A-Za-z0-9_]{20,255}/,
    /(?<![A-Za-z0-9])[A-Za-z0-9+/_=-]{40,}(?![A-Za-z0-9])/,
  ];
  return patterns.some((pattern) => pattern.test(rawContents));
}

function canonicalWithoutVersion(secretEntry) {
  const clone = JSON.parse(JSON.stringify(secretEntry));
  delete clone.secretVersion;
  return clone;
}

function ensureSecretVersionBump(previousManifest, currentManifest) {
  const previous = new Map(
    (Array.isArray(previousManifest.secrets) ? previousManifest.secrets : []).map((entry) => [entry.secretName, entry]),
  );
  const current = Array.isArray(currentManifest.secrets) ? currentManifest.secrets : [];

  for (const currentEntry of current) {
    if (!previous.has(currentEntry.secretName)) {
      continue;
    }
    const previousEntry = previous.get(currentEntry.secretName);
    const previousWithoutVersion = JSON.stringify(canonicalWithoutVersion(previousEntry));
    const currentWithoutVersion = JSON.stringify(canonicalWithoutVersion(currentEntry));
    if (previousWithoutVersion !== currentWithoutVersion && Number(currentEntry.secretVersion) <= Number(previousEntry.secretVersion)) {
      fail(
        "SECRET_VERSION_BUMP_REQUIRED",
        "secretVersion must increment when secret metadata changes",
        {
          secretName: currentEntry.secretName,
          previousVersion: previousEntry.secretVersion,
          currentVersion: currentEntry.secretVersion,
        },
      );
    }
  }
}

function main() {
  const args = parseArgs(process.argv);
  if (!fs.existsSync(args.manifestPath)) {
    fail("SECRET_MANIFEST_MISSING", "Secret manifest file is missing", {
      manifestPath: args.manifestPath,
    });
  }

  const rawContents = fs.readFileSync(args.manifestPath, "utf8");
  if (hasSuspiciousSecretPatterns(rawContents)) {
    fail("SECRET_VALUE_COMMITTED", "Potential secret value detected in secret manifest file", {
      manifestPath: args.manifestPath,
    });
  }

  const manifest = readJson(args.manifestPath);
  const validation = validateSecretSchema(manifest);
  if (!validation.valid) {
    fail("SECRET_MANIFEST_INVALID", "Secret manifest schema validation failed", {
      errors: validation.errors,
    });
  }

  const canonicalA = JSON.stringify(getCanonicalSecretManifest(manifest));
  const canonicalB = JSON.stringify(getCanonicalSecretManifest(JSON.parse(canonicalA)));
  if (canonicalA !== canonicalB) {
    fail("SECRET_MANIFEST_NON_DETERMINISTIC", "Secret manifest canonicalization is non-deterministic");
  }

  const manifestHash = computeSecretManifestHash(manifest);

  if (args.previousManifestPath && fs.existsSync(args.previousManifestPath)) {
    const previousManifest = readJson(args.previousManifestPath);
    const previousValidation = validateSecretSchema(previousManifest);
    if (!previousValidation.valid) {
      fail("SECRET_PREVIOUS_MANIFEST_INVALID", "Previous secret manifest is invalid", {
        errors: previousValidation.errors,
      });
    }
    const previousCanonical = getCanonicalSecretManifest(previousManifest);
    const currentCanonical = getCanonicalSecretManifest(manifest);
    const previousHash = computeSecretManifestHash(previousCanonical);
    const currentHash = computeSecretManifestHash(currentCanonical);

    if (previousHash !== currentHash) {
      ensureSecretVersionBump(previousCanonical, currentCanonical);
    }
  }

  const payload = {
    ok: true,
    secret_manifest_hash: manifestHash,
    secret_count: manifest.secrets.length,
  };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
}

main();
