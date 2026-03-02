"use strict";

const path = require("node:path");

function loadDistModule() {
  const candidates = [
    path.resolve(__dirname, "../dist/src/security/workload-manifest.js"),
    path.resolve(__dirname, "../../dist/src/security/workload-manifest.js"),
  ];

  for (const candidate of candidates) {
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      return require(candidate);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "MODULE_NOT_FOUND") {
        continue;
      }
      throw error;
    }
  }

  const error = new Error(
    "Compiled workload manifest module not found. Run `npm --prefix openclaw-bridge run bridge:build` first.",
  );
  error.code = "WORKLOAD_BUILD_REQUIRED";
  throw error;
}

module.exports = loadDistModule();
