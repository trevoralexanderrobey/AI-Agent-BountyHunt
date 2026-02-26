function normalizeVersionString(rawVersion) {
  return typeof rawVersion === "string" ? rawVersion.trim() : "";
}

function parseVersion(rawVersion) {
  const value = normalizeVersionString(rawVersion);
  if (!value) {
    return {
      valid: false,
      raw: value,
      normalized: "",
      major: null,
      minor: null,
      patch: null,
    };
  }

  const match = value.match(/^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) {
    return {
      valid: false,
      raw: value,
      normalized: "",
      major: null,
      minor: null,
      patch: null,
    };
  }

  const major = Number.parseInt(match[1], 10);
  const minor = Number.parseInt(match[2], 10);
  const patch = Number.parseInt(match[3], 10);

  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) {
    return {
      valid: false,
      raw: value,
      normalized: "",
      major: null,
      minor: null,
      patch: null,
    };
  }

  return {
    valid: true,
    raw: value,
    normalized: `${major}.${minor}.${patch}`,
    major,
    minor,
    patch,
  };
}

function createVersionGuard() {
  function evaluateCompatibility(localVersion, remoteVersion) {
    const local = parseVersion(localVersion);
    const remote = parseVersion(remoteVersion);

    if (!local.valid || !remote.valid) {
      return {
        compatible: false,
        reason: "invalid_version",
        startupFatal: true,
        local,
        remote,
      };
    }

    if (local.major !== remote.major) {
      return {
        compatible: false,
        reason: "major_mismatch",
        startupFatal: true,
        local,
        remote,
      };
    }

    if (Math.abs(local.minor - remote.minor) > 1) {
      return {
        compatible: false,
        reason: "minor_skew_exceeded",
        startupFatal: false,
        local,
        remote,
      };
    }

    return {
      compatible: true,
      reason: "compatible",
      startupFatal: false,
      local,
      remote,
    };
  }

  function isCoexistenceAllowed(localVersion, remoteVersion) {
    return evaluateCompatibility(localVersion, remoteVersion).compatible;
  }

  return {
    parseVersion,
    evaluateCompatibility,
    isCoexistenceAllowed,
  };
}

module.exports = {
  createVersionGuard,
  parseVersion,
};
