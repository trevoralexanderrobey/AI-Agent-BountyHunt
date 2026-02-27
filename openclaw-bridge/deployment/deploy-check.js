const fs = require("node:fs");
const path = require("node:path");

const { runPreflightValidation } = require("./preflight-validator.js");

const REQUIRED_DEPLOYMENT_DOCS = [
  "topology-model.md",
  "operational-playbook.md",
  "scaling-strategy.md",
  "security-model.md",
  "disaster-recovery.md",
  "slo-sli-spec.md",
  "infrastructure-reference.md",
];

const REQUIRED_TOOLING_FILES = ["preflight-validator.js", "deploy-check.js"];

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

function parsePositiveInt(value) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function resolvePath(value) {
  return path.resolve(String(value));
}

function checkRequiredFiles(baseDir, fileNames) {
  const missing = [];
  const present = [];

  for (const fileName of fileNames) {
    const absolutePath = path.join(baseDir, fileName);
    if (!fs.existsSync(absolutePath)) {
      missing.push({ file: fileName, path: absolutePath });
      continue;
    }

    const stat = fs.statSync(absolutePath);
    if (!stat.isFile() || stat.size === 0) {
      missing.push({ file: fileName, path: absolutePath });
      continue;
    }

    present.push({ file: fileName, path: absolutePath });
  }

  return { missing, present };
}

async function runDeployCheck(options = {}) {
  const deploymentDir = path.resolve(__dirname);
  const errors = [];
  const warnings = [];

  const preflightOptions = {
    ...options,
    includeDiagnostics: parseBoolean(options.includeDiagnostics, true),
  };

  const preflightResult = await runPreflightValidation(preflightOptions);

  for (const warning of preflightResult.warnings || []) {
    warnings.push(warning);
  }

  for (const error of preflightResult.errors || []) {
    errors.push(error);
  }

  const docsCheck = checkRequiredFiles(deploymentDir, REQUIRED_DEPLOYMENT_DOCS);
  if (docsCheck.missing.length > 0) {
    errors.push({
      code: "DEPLOYMENT_DOC_MISSING",
      message: "One or more required deployment documents are missing or empty",
      details: {
        missing: docsCheck.missing,
      },
    });
  }

  const toolsCheck = checkRequiredFiles(deploymentDir, REQUIRED_TOOLING_FILES);
  if (toolsCheck.missing.length > 0) {
    errors.push({
      code: "DEPLOYMENT_TOOLING_MISSING",
      message: "One or more required deployment tooling files are missing or empty",
      details: {
        missing: toolsCheck.missing,
      },
    });
  }

  const result = {
    ready_for_production: errors.length === 0,
    warnings,
    errors,
    checks: {
      preflight: {
        ready_for_production: Boolean(preflightResult.ready_for_production),
      },
      docs: {
        required: REQUIRED_DEPLOYMENT_DOCS,
        present: docsCheck.present,
        missing: docsCheck.missing,
      },
      tooling: {
        required: REQUIRED_TOOLING_FILES,
        present: toolsCheck.present,
        missing: toolsCheck.missing,
      },
    },
  };

  if (parseBoolean(options.includeDiagnostics, false) !== true) {
    delete result.checks;
  }

  return result;
}

function parseCliArgs(argv) {
  const args = Array.isArray(argv) ? argv.slice(2) : [];
  const parsed = {
    includeDiagnostics: true,
  };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--config") {
      parsed.__configPath = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--env") {
      parsed.__cliEnv = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--metrics-endpoint") {
      parsed.liveCheck = parsed.liveCheck || {};
      parsed.liveCheck.metricsEndpoint = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--expected-node-count") {
      parsed.topology = parsed.topology || {};
      parsed.topology.expectedNodeCount = parsePositiveInt(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--version-target") {
      parsed.deployment = parsed.deployment || {};
      if (!Array.isArray(parsed.deployment.versionTargets)) {
        parsed.deployment.versionTargets = [];
      }
      const value = normalizeString(args[index + 1]);
      if (value) {
        parsed.deployment.versionTargets.push(value);
      }
      index += 1;
      continue;
    }
    if (token === "--no-diagnostics") {
      parsed.includeDiagnostics = false;
      continue;
    }
  }

  return parsed;
}

function loadConfigFromPath(configPath) {
  const resolved = resolvePath(configPath);
  const raw = fs.readFileSync(resolved, "utf8");
  return JSON.parse(raw);
}

if (require.main === module) {
  (async () => {
    const cliOptions = parseCliArgs(process.argv);

    let fileOptions = {};
    if (cliOptions.__configPath) {
      fileOptions = loadConfigFromPath(cliOptions.__configPath);
    }

    const merged = {
      ...fileOptions,
      ...cliOptions,
      topology: {
        ...(fileOptions.topology || {}),
        ...(cliOptions.topology || {}),
      },
      deployment: {
        ...(fileOptions.deployment || {}),
        ...(cliOptions.deployment || {}),
      },
      liveCheck: {
        ...(fileOptions.liveCheck || {}),
        ...(cliOptions.liveCheck || {}),
      },
    };

    const result = await runDeployCheck(merged);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exit(result.errors.length === 0 ? 0 : 1);
  })().catch((error) => {
    const output = {
      ready_for_production: false,
      warnings: [],
      errors: [
        {
          code: "DEPLOY_CHECK_RUNTIME_ERROR",
          message: error && error.message ? error.message : String(error),
          details: {},
        },
      ],
    };
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    process.exit(1);
  });
}

module.exports = {
  runDeployCheck,
};
