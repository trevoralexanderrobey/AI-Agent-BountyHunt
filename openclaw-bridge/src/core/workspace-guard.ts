import fs from "node:fs/promises";
import path from "node:path";

function isWindowsPlatform(): boolean {
  return process.platform === "win32";
}

function normalizePathForComparison(value: string): string {
  const normalized = path.normalize(value);
  const withoutTrailingSeparators = normalized.replace(new RegExp(`[${path.sep.replace("\\", "\\\\")}]+$`), "");
  return isWindowsPlatform() ? withoutTrailingSeparators.toLowerCase() : withoutTrailingSeparators;
}

async function resolveExistingPath(targetPath: string): Promise<string> {
  try {
    return await fs.realpath(targetPath);
  } catch {
    const parent = path.dirname(targetPath);
    if (parent === targetPath) {
      throw Object.assign(new Error("Path is outside workspace"), {
        code: "PATH_OUTSIDE_WORKSPACE",
      });
    }
    const canonicalParent = await resolveExistingPath(parent);
    return path.join(canonicalParent, path.basename(targetPath));
  }
}

export async function canonicalizeWorkspaceRoot(workspaceRoot: string): Promise<string> {
  const resolvedRoot = path.resolve(String(workspaceRoot || "").trim());
  if (!resolvedRoot) {
    throw Object.assign(new Error("Workspace root is invalid"), {
      code: "INVALID_WORKSPACE_ROOT",
    });
  }
  return fs.realpath(resolvedRoot);
}

export async function assertPathInsideWorkspace(inputPath: string, canonicalWorkspaceRoot: string): Promise<string> {
  const candidateRaw = String(inputPath || "").trim();
  if (!candidateRaw || candidateRaw === "." || candidateRaw === "..") {
    throw Object.assign(new Error("Path is outside workspace"), {
      code: "PATH_OUTSIDE_WORKSPACE",
    });
  }
  if (path.win32.isAbsolute(candidateRaw) && !isWindowsPlatform()) {
    throw Object.assign(new Error("Path is outside workspace"), {
      code: "PATH_OUTSIDE_WORKSPACE",
    });
  }

  const canonicalRoot = normalizePathForComparison(path.resolve(canonicalWorkspaceRoot));
  const resolvedPath = path.resolve(canonicalRoot, candidateRaw);
  const canonicalCandidate = await resolveExistingPath(resolvedPath);
  const normalizedCandidate = normalizePathForComparison(canonicalCandidate);
  const rootWithSep = canonicalRoot.endsWith(path.sep) ? canonicalRoot : `${canonicalRoot}${path.sep}`;

  if (normalizedCandidate !== canonicalRoot && !normalizedCandidate.startsWith(rootWithSep)) {
    throw Object.assign(new Error("Path is outside workspace"), {
      code: "PATH_OUTSIDE_WORKSPACE",
    });
  }

  return canonicalCandidate;
}
