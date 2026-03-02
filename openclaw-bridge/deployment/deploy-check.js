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
const REQUIRED_PHASE21_DOCS = [
  path.resolve(__dirname, "..", "docs", "secret-governance.md"),
  path.resolve(__dirname, "..", "docs", "threat-model.md"),
  path.resolve(__dirname, "..", "docs", "observability-spec.md"),
  path.resolve(__dirname, "..", "docs", "http-api-spec.md"),
  path.resolve(__dirname, "..", "docs", "execution-plane-activation-spec.md"),
];
const REQUIRED_PHASE22_FILES = [
  path.resolve(__dirname, "..", "policy", "execution-policy-manifest.js"),
  path.resolve(__dirname, "..", "policy", "policy-authority.js"),
  path.resolve(__dirname, "..", "policy", "policy-runtime.js"),
  path.resolve(__dirname, "..", "policy", "execution-policy.json"),
  path.resolve(__dirname, "..", "policy", "execution-policy.json.sig"),
  path.resolve(__dirname, "..", "policy", "execution-policy.pub.pem"),
  path.resolve(__dirname, "..", "policy", "verify-policy-artifact.js"),
];
const REQUIRED_PHASE23_FILES = [
  path.resolve(__dirname, "..", "security", "secret-manifest.js"),
  path.resolve(__dirname, "..", "security", "secret-manifest.json"),
  path.resolve(__dirname, "..", "security", "secret-authority.js"),
  path.resolve(__dirname, "..", "security", "verify-secret-manifest.js"),
  path.resolve(__dirname, "..", "security", "validate-phase23.js"),
];
const REQUIRED_PHASE24_FILES = [
  path.resolve(__dirname, "..", "src", "security", "workload-manifest.ts"),
  path.resolve(__dirname, "..", "src", "security", "workload-integrity.ts"),
  path.resolve(__dirname, "..", "security", "workload-manifest.js"),
  path.resolve(__dirname, "..", "security", "workload-integrity.js"),
  path.resolve(__dirname, "..", "security", "workload-manifest.json"),
  path.resolve(__dirname, "..", "security", "workload-manifest.hash"),
  path.resolve(__dirname, "..", "scripts", "verify-workload-manifest.ts"),
  path.resolve(__dirname, "..", "scripts", "validate-phase24.ts"),
];
const REQUIRED_PHASE25_FILES = [
  path.resolve(__dirname, "..", "src", "security", "workload-attestation.ts"),
  path.resolve(__dirname, "..", "security", "workload-attestation.js"),
  path.resolve(__dirname, "..", "security", "workload-attestation-reference.json"),
  path.resolve(__dirname, "..", "security", "workload-attestation-reference.hash"),
  path.resolve(__dirname, "..", "scripts", "verify-workload-attestation.ts"),
  path.resolve(__dirname, "..", "scripts", "validate-phase25.ts"),
];

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

function checkRequiredAbsoluteFiles(paths) {
  const missing = [];
  const present = [];
  for (const absolutePath of paths) {
    if (!fs.existsSync(absolutePath)) {
      missing.push({ path: absolutePath });
      continue;
    }
    const stat = fs.statSync(absolutePath);
    if (!stat.isFile() || stat.size === 0) {
      missing.push({ path: absolutePath });
      continue;
    }
    present.push({ path: absolutePath });
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

  const phase21DocsCheck = checkRequiredAbsoluteFiles(REQUIRED_PHASE21_DOCS);
  if (phase21DocsCheck.missing.length > 0) {
    errors.push({
      code: "PHASE21_GOVERNANCE_DOC_MISSING",
      message: "One or more Phase 21 governance documents are missing or empty",
      details: {
        missing: phase21DocsCheck.missing,
      },
    });
  }


  const phase22PolicyCheck = checkRequiredAbsoluteFiles(REQUIRED_PHASE22_FILES);
  if (phase22PolicyCheck.missing.length > 0) {
    errors.push({
      code: "PHASE22_POLICY_GOVERNANCE_MISSING",
      message: "One or more Phase 22 policy governance files are missing or empty",
      details: {
        missing: phase22PolicyCheck.missing,
      },
    });
  }

  const phase23SecretCheck = checkRequiredAbsoluteFiles(REQUIRED_PHASE23_FILES);
  if (phase23SecretCheck.missing.length > 0) {
    errors.push({
      code: "PHASE23_SECRET_GOVERNANCE_MISSING",
      message: "One or more Phase 23 secret governance files are missing or empty",
      details: {
        missing: phase23SecretCheck.missing,
      },
    });
  }

  const phase24WorkloadCheck = checkRequiredAbsoluteFiles(REQUIRED_PHASE24_FILES);
  if (phase24WorkloadCheck.missing.length > 0) {
    errors.push({
      code: "PHASE24_WORKLOAD_GOVERNANCE_MISSING",
      message: "One or more Phase 24 workload governance files are missing or empty",
      details: {
        missing: phase24WorkloadCheck.missing,
      },
    });
  }

  const phase25AttestationCheck = checkRequiredAbsoluteFiles(REQUIRED_PHASE25_FILES);
  if (phase25AttestationCheck.missing.length > 0) {
    errors.push({
      code: "PHASE25_ATTESTATION_GOVERNANCE_MISSING",
      message: "One or more Phase 25 attestation governance files are missing or empty",
      details: {
        missing: phase25AttestationCheck.missing,
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
      phase21Docs: {
        required: REQUIRED_PHASE21_DOCS,
        present: phase21DocsCheck.present,
        missing: phase21DocsCheck.missing,
      },
      workflow: {
        required: [],
        present: [],
        missing: [],
      },
      phase22Policy: {
        required: REQUIRED_PHASE22_FILES,
        present: phase22PolicyCheck.present,
        missing: phase22PolicyCheck.missing,
      },
      phase23Secrets: {
        required: REQUIRED_PHASE23_FILES,
        present: phase23SecretCheck.present,
        missing: phase23SecretCheck.missing,
      },
      phase24Workload: {
        required: REQUIRED_PHASE24_FILES,
        present: phase24WorkloadCheck.present,
        missing: phase24WorkloadCheck.missing,
      },
      phase25Attestation: {
        required: REQUIRED_PHASE25_FILES,
        present: phase25AttestationCheck.present,
        missing: phase25AttestationCheck.missing,
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
    if (token === "--execution-mode") {
      parsed.execution = parsed.execution || {};
      parsed.execution.executionMode = normalizeString(args[index + 1]).toLowerCase();
      index += 1;
      continue;
    }
    if (token === "--execution-backend") {
      parsed.execution = parsed.execution || {};
      parsed.execution.backend = normalizeString(args[index + 1]).toLowerCase();
      index += 1;
      continue;
    }
    if (token === "--container-runtime-enabled") {
      parsed.execution = parsed.execution || {};
      parsed.execution.containerRuntimeEnabled = parseBoolean(args[index + 1], false);
      index += 1;
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
      execution: {
        ...(fileOptions.execution || {}),
        ...(cliOptions.execution || {}),
        tools: {
          ...((fileOptions.execution && fileOptions.execution.tools) || {}),
          ...((cliOptions.execution && cliOptions.execution.tools) || {}),
        },
        resourcePolicies: {
          ...((fileOptions.execution && fileOptions.execution.resourcePolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.resourcePolicies) || {}),
        },
        sandboxPolicies: {
          ...((fileOptions.execution && fileOptions.execution.sandboxPolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.sandboxPolicies) || {}),
        },
        egressPolicies: {
          ...((fileOptions.execution && fileOptions.execution.egressPolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.egressPolicies) || {}),
        },
        imagePolicies: {
          ...((fileOptions.execution && fileOptions.execution.imagePolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.imagePolicies) || {}),
        },
        images: {
          ...((fileOptions.execution && fileOptions.execution.images) || {}),
          ...((cliOptions.execution && cliOptions.execution.images) || {}),
        },
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
