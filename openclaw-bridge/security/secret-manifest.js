const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REQUIRED_ROOT_KEYS = Object.freeze(["secrets"]);
const REQUIRED_SECRET_KEYS = Object.freeze([
  "secretName",
  "allowedTools",
  "allowedPrincipals",
  "rotationPolicy",
  "secretVersion",
  "injectionMode",
  "productionRequired",
]);
const ALLOWED_ROOT_KEYS = REQUIRED_ROOT_KEYS;
const ALLOWED_SECRET_KEYS = REQUIRED_SECRET_KEYS;

const FORBIDDEN_KEY_PATTERN =
  /(value|secretvalue|secret_value|token|privatekey|private_key|timestamp|createdat|updatedat|nodeid|node_id|hostname|host_id)/i;

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function hasUnknownKeys(rawObject, allowedKeys) {
  const allowed = new Set(allowedKeys);
  return Object.keys(rawObject).filter((key) => !allowed.has(key));
}

function validateAllowedStringArray(value, fieldPath, errors) {
  if (!Array.isArray(value) || value.length === 0) {
    errors.push(`${fieldPath} must be a non-empty array`);
    return;
  }

  const seen = new Set();
  for (const item of value) {
    const normalized = normalizeString(item).toLowerCase();
    if (!normalized) {
      errors.push(`${fieldPath} contains an empty string`);
      continue;
    }
    if (seen.has(normalized)) {
      errors.push(`${fieldPath} contains duplicate entry '${normalized}'`);
      continue;
    }
    seen.add(normalized);
  }
}

function hasForbiddenKeys(value) {
  if (!value || typeof value !== "object") {
    return false;
  }

  if (Array.isArray(value)) {
    return value.some((item) => hasForbiddenKeys(item));
  }

  return Object.entries(value).some(([key, child]) => {
    if (FORBIDDEN_KEY_PATTERN.test(String(key || ""))) {
      return true;
    }
    return hasForbiddenKeys(child);
  });
}

function validateSecretSchema(manifest) {
  const errors = [];

  if (!isPlainObject(manifest)) {
    return {
      valid: false,
      errors: ["secret manifest must be an object"],
    };
  }

  for (const key of REQUIRED_ROOT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(manifest, key)) {
      errors.push(`missing required field '${key}'`);
    }
  }

  const rootUnknown = hasUnknownKeys(manifest, ALLOWED_ROOT_KEYS);
  if (rootUnknown.length > 0) {
    errors.push(`unknown root fields: ${rootUnknown.join(",")}`);
  }

  if (!Array.isArray(manifest.secrets)) {
    errors.push("secrets must be an array");
  } else {
    const seenSecretNames = new Set();
    for (let index = 0; index < manifest.secrets.length; index += 1) {
      const entry = manifest.secrets[index];
      const fieldPath = `secrets[${index}]`;

      if (!isPlainObject(entry)) {
        errors.push(`${fieldPath} must be an object`);
        continue;
      }

      for (const key of REQUIRED_SECRET_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(entry, key)) {
          errors.push(`${fieldPath}.${key} is required`);
        }
      }

      const unknown = hasUnknownKeys(entry, ALLOWED_SECRET_KEYS);
      if (unknown.length > 0) {
        errors.push(`${fieldPath} contains unknown keys: ${unknown.join(",")}`);
      }

      const secretName = normalizeString(entry.secretName);
      if (!secretName) {
        errors.push(`${fieldPath}.secretName must be a non-empty string`);
      } else {
        const key = secretName.toLowerCase();
        if (seenSecretNames.has(key)) {
          errors.push(`duplicate secretName '${secretName}'`);
        } else {
          seenSecretNames.add(key);
        }
      }

      validateAllowedStringArray(entry.allowedTools, `${fieldPath}.allowedTools`, errors);

      if (entry.allowedPrincipals !== "*") {
        validateAllowedStringArray(entry.allowedPrincipals, `${fieldPath}.allowedPrincipals`, errors);
      }

      if (!isPlainObject(entry.rotationPolicy)) {
        errors.push(`${fieldPath}.rotationPolicy must be an object`);
      }

      if (!isPositiveInteger(entry.secretVersion)) {
        errors.push(`${fieldPath}.secretVersion must be a positive integer`);
      }

      if (normalizeString(entry.injectionMode) !== "env-only") {
        errors.push(`${fieldPath}.injectionMode must be 'env-only'`);
      }

      if (typeof entry.productionRequired !== "boolean") {
        errors.push(`${fieldPath}.productionRequired must be a boolean`);
      }

      if (hasForbiddenKeys(entry)) {
        errors.push(`${fieldPath} contains forbidden metadata keys`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

function stableSortArray(values) {
  return values
    .slice()
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function normalizeSecretEntry(entry) {
  const secretName = normalizeString(entry.secretName);
  const allowedTools = Array.isArray(entry.allowedTools)
    ? Array.from(
        new Set(
          entry.allowedTools
            .map((item) => normalizeString(item).toLowerCase())
            .filter(Boolean),
        ),
      ).sort((a, b) => a.localeCompare(b))
    : [];
  const allowedPrincipals =
    entry.allowedPrincipals === "*"
      ? "*"
      : Array.from(
          new Set(
            (Array.isArray(entry.allowedPrincipals) ? entry.allowedPrincipals : [])
              .map((item) => normalizeString(item))
              .filter(Boolean),
          ),
        ).sort((a, b) => a.localeCompare(b));

  const canonicalRotationPolicy = canonicalize(entry.rotationPolicy || {});

  return {
    secretName,
    allowedTools,
    allowedPrincipals,
    rotationPolicy: canonicalRotationPolicy,
    secretVersion: Number(entry.secretVersion),
    injectionMode: "env-only",
    productionRequired: entry.productionRequired === true,
  };
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return stableSortArray(value.map((item) => canonicalize(item)));
  }

  if (!isPlainObject(value)) {
    return value;
  }

  const ordered = {};
  for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
    ordered[key] = canonicalize(value[key]);
  }
  return ordered;
}

function getCanonicalSecretManifest(inputManifest) {
  const validation = validateSecretSchema(inputManifest);
  if (!validation.valid) {
    const error = new Error(`Secret manifest schema validation failed: ${validation.errors.join("; ")}`);
    error.code = "SECRET_MANIFEST_SCHEMA_INVALID";
    error.details = {
      errors: validation.errors,
    };
    throw error;
  }

  const normalized = {
    secrets: inputManifest.secrets.map((entry) => normalizeSecretEntry(entry)),
  };

  normalized.secrets.sort((a, b) => a.secretName.localeCompare(b.secretName));
  return canonicalize(normalized);
}

function computeSecretManifestHash(inputManifest) {
  const canonical = getCanonicalSecretManifest(inputManifest);
  const canonicalJson = JSON.stringify(canonical);
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

function loadSecretManifestFromDisk(options = {}) {
  const canonicalPath = path.resolve(__dirname, "secret-manifest.json");
  const providedManifestPath =
    normalizeString(options.manifestPath) || normalizeString(process.env.SECRET_MANIFEST_PATH) || "";
  const production = Boolean(
    options.production === true || String(process.env.NODE_ENV || "").trim().toLowerCase() === "production",
  );

  if (production) {
    if (providedManifestPath) {
      const err = new Error("Manifest path override not allowed in production");
      err.code = "SECRET_MANIFEST_OVERRIDE_IN_PRODUCTION";
      throw err;
    }

    const manifestPath = canonicalPath;
    let writable = false;
    try {
      fs.accessSync(manifestPath, fs.constants.W_OK);
      writable = true;
    } catch (err) {
      // accessSync throws when not writable or file doesn't exist - that's acceptable here
      writable = false;
    }

    if (writable) {
      const error = new Error("Secret manifest must be read-only in production");
      error.code = "SECRET_MANIFEST_WRITABLE_IN_PRODUCTION";
      throw error;
    }

    const raw = fs.readFileSync(manifestPath, "utf8");
    return JSON.parse(raw);
  }

  // Non-production: allow explicit overrides for local/dev convenience.
  const manifestPath = providedManifestPath || canonicalPath;
  const raw = fs.readFileSync(manifestPath, "utf8");
  return JSON.parse(raw);
}

module.exports = {
  validateSecretSchema,
  computeSecretManifestHash,
  getCanonicalSecretManifest,
  loadSecretManifestFromDisk,
};
