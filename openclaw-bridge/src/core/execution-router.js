"use strict";

const path = require("node:path");

function loadDistRouter() {
  const candidates = [
    path.resolve(__dirname, "../../dist/src/core/execution-router.js"),
    path.resolve(__dirname, "../../../dist/src/core/execution-router.js"),
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
    "Compiled execution router not found. Run `npm --prefix openclaw-bridge run bridge:build` before using JS runtime entrypoints.",
  );
  error.code = "ROUTER_BUILD_REQUIRED";
  throw error;
}

const mod = loadDistRouter();

if (!mod || typeof mod.createExecutionRouter !== "function") {
  const error = new Error("Compiled execution router module is invalid.");
  error.code = "ROUTER_BUILD_REQUIRED";
  throw error;
}

module.exports = {
  createExecutionRouter: mod.createExecutionRouter,
};
