import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  WorkloadManifest,
  WorkloadManifestEntry,
  computeWorkloadManifestHash,
  getCanonicalWorkloadManifest,
  resolveDefaultWorkloadManifestPath,
  validateWorkloadManifest,
} from "../src/security/workload-manifest";

interface VerificationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  manifestPath: string;
  manifestHash: string;
  deterministic: boolean;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseArgs(argv: string[]): { manifestPath?: string; expectedHash?: string; expectedHashFile?: string } {
  const args = argv.slice(2);
  const parsed: { manifestPath?: string; expectedHash?: string; expectedHashFile?: string } = {};

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (token === "--manifest" && args[i + 1]) {
      parsed.manifestPath = args[i + 1];
      i += 1;
      continue;
    }
    if (token === "--expected-hash" && args[i + 1]) {
      parsed.expectedHash = args[i + 1];
      i += 1;
      continue;
    }
    if (token === "--expected-hash-file" && args[i + 1]) {
      parsed.expectedHashFile = args[i + 1];
      i += 1;
      continue;
    }
  }

  return parsed;
}

function resolveExpectedHash(parsed: { expectedHash?: string; expectedHashFile?: string }): string {
  if (parsed.expectedHash) {
    return normalizeString(parsed.expectedHash).toLowerCase();
  }
  if (parsed.expectedHashFile) {
    const content = fs.readFileSync(path.resolve(parsed.expectedHashFile), "utf8");
    return normalizeString(content).toLowerCase();
  }

  const fromEnv = normalizeString(process.env.WORKLOAD_MANIFEST_EXPECTED_HASH).toLowerCase();
  if (fromEnv) {
    return fromEnv;
  }

  const hashFile = path.resolve(path.dirname(resolveDefaultWorkloadManifestPath()), "workload-manifest.hash");
  if (fs.existsSync(hashFile)) {
    return normalizeString(fs.readFileSync(hashFile, "utf8")).toLowerCase();
  }

  return "";
}

function loadManifest(manifestPath: string): WorkloadManifest {
  return JSON.parse(fs.readFileSync(manifestPath, "utf8")) as WorkloadManifest;
}

function stripVersion(entry: WorkloadManifestEntry): Record<string, unknown> {
  return {
    workloadID: entry.workloadID,
    adapterHash: entry.adapterHash,
    entrypointHash: entry.entrypointHash,
    runtimeConfigHash: entry.runtimeConfigHash,
    containerImageDigest: entry.containerImageDigest || "",
    productionRequired: entry.productionRequired === true,
  };
}

function readPreviousManifestFromGit(manifestPath: string): WorkloadManifest | null {
  const repoRoot = path.resolve(path.dirname(manifestPath), "..", "..");
  const relativeManifestPath = path.relative(repoRoot, manifestPath).split(path.sep).join("/");
  try {
    const raw = execSync(`git -C ${JSON.stringify(repoRoot)} show HEAD:${relativeManifestPath}`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return JSON.parse(raw) as WorkloadManifest;
  } catch {
    return null;
  }
}

function enforceVersionBump(
  currentManifest: WorkloadManifest,
  previousManifest: WorkloadManifest | null,
  errors: string[],
): void {
  if (!previousManifest) {
    return;
  }

  let previousCanonical: WorkloadManifest;
  try {
    previousCanonical = getCanonicalWorkloadManifest(previousManifest);
  } catch {
    return;
  }

  const previousByID = new Map(
    previousCanonical.workloads.map((entry) => [normalizeString(entry.workloadID), entry]),
  );

  for (const current of currentManifest.workloads) {
    const id = normalizeString(current.workloadID);
    const previous = previousByID.get(id);
    if (!previous) {
      continue;
    }

    const changed = JSON.stringify(stripVersion(current)) !== JSON.stringify(stripVersion(previous));
    if (!changed) {
      continue;
    }

    if (Number(current.workloadVersion) <= Number(previous.workloadVersion)) {
      errors.push(
        `workloadVersion must increase for '${id}' when workload metadata changes (previous=${previous.workloadVersion}, current=${current.workloadVersion})`,
      );
    }
  }
}

function rejectProductionImageTags(manifest: WorkloadManifest, errors: string[]): void {
  for (const entry of manifest.workloads) {
    if (entry.productionRequired !== true) {
      continue;
    }

    const digest = normalizeString(entry.containerImageDigest).toLowerCase();
    if (!digest) {
      errors.push(`containerImageDigest is required for production workload '${entry.workloadID}'`);
      continue;
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
      errors.push(`containerImageDigest must be digest-pinned for production workload '${entry.workloadID}'`);
    }
  }
}

function runVerification(args: { manifestPath?: string; expectedHash?: string; expectedHashFile?: string }): VerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const manifestPath = path.resolve(args.manifestPath || resolveDefaultWorkloadManifestPath());
  if (!fs.existsSync(manifestPath)) {
    return {
      ok: false,
      errors: [`workload manifest is missing: ${manifestPath}`],
      warnings,
      manifestPath,
      manifestHash: "",
      deterministic: false,
    };
  }

  let rawManifest: WorkloadManifest;
  try {
    rawManifest = loadManifest(manifestPath);
  } catch (error) {
    return {
      ok: false,
      errors: [`unable to parse workload manifest: ${error instanceof Error ? error.message : String(error)}`],
      warnings,
      manifestPath,
      manifestHash: "",
      deterministic: false,
    };
  }

  const validation = validateWorkloadManifest(rawManifest);
  if (!validation.valid) {
    errors.push(...validation.errors);
    return {
      ok: false,
      errors,
      warnings,
      manifestPath,
      manifestHash: "",
      deterministic: false,
    };
  }

  const canonical = getCanonicalWorkloadManifest(rawManifest);
  const hashA = computeWorkloadManifestHash(canonical);
  const hashB = computeWorkloadManifestHash(JSON.parse(JSON.stringify(canonical)));
  const deterministic = hashA === hashB;
  if (!deterministic) {
    errors.push("canonical workload manifest hash is non-deterministic");
  }

  const expectedHash = resolveExpectedHash(args);
  if (expectedHash && expectedHash !== hashA) {
    errors.push(`expected hash mismatch (expected=${expectedHash}, actual=${hashA})`);
  }

  const previousManifest = readPreviousManifestFromGit(manifestPath);
  enforceVersionBump(canonical, previousManifest, errors);
  rejectProductionImageTags(canonical, errors);

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    manifestPath,
    manifestHash: hashA,
    deterministic,
  };
}

function main(): void {
  const args = parseArgs(process.argv);
  const result = runVerification(args);

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exit(result.ok ? 0 : 1);
}

main();
