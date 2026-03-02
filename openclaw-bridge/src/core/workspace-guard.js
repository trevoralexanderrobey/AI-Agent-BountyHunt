"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.canonicalizeWorkspaceRoot = canonicalizeWorkspaceRoot;
exports.assertPathInsideWorkspace = assertPathInsideWorkspace;
const promises_1 = __importDefault(require("node:fs/promises"));
const node_path_1 = __importDefault(require("node:path"));
function isWindowsPlatform() {
    return process.platform === "win32";
}
function normalizePathForComparison(value) {
    const normalized = node_path_1.default.normalize(value);
    const withoutTrailingSeparators = normalized.replace(new RegExp(`[${node_path_1.default.sep.replace("\\", "\\\\")}]+$`), "");
    return isWindowsPlatform() ? withoutTrailingSeparators.toLowerCase() : withoutTrailingSeparators;
}
async function resolveExistingPath(targetPath) {
    try {
        return await promises_1.default.realpath(targetPath);
    }
    catch {
        const parent = node_path_1.default.dirname(targetPath);
        if (parent === targetPath) {
            throw Object.assign(new Error("Path is outside workspace"), {
                code: "PATH_OUTSIDE_WORKSPACE",
            });
        }
        const canonicalParent = await resolveExistingPath(parent);
        return node_path_1.default.join(canonicalParent, node_path_1.default.basename(targetPath));
    }
}
async function canonicalizeWorkspaceRoot(workspaceRoot) {
    const resolvedRoot = node_path_1.default.resolve(String(workspaceRoot || "").trim());
    if (!resolvedRoot) {
        throw Object.assign(new Error("Workspace root is invalid"), {
            code: "INVALID_WORKSPACE_ROOT",
        });
    }
    return promises_1.default.realpath(resolvedRoot);
}
async function assertPathInsideWorkspace(inputPath, canonicalWorkspaceRoot) {
    const candidateRaw = String(inputPath || "").trim();
    if (!candidateRaw || candidateRaw === "." || candidateRaw === "..") {
        throw Object.assign(new Error("Path is outside workspace"), {
            code: "PATH_OUTSIDE_WORKSPACE",
        });
    }
    if (node_path_1.default.win32.isAbsolute(candidateRaw) && !isWindowsPlatform()) {
        throw Object.assign(new Error("Path is outside workspace"), {
            code: "PATH_OUTSIDE_WORKSPACE",
        });
    }
    const canonicalRoot = normalizePathForComparison(node_path_1.default.resolve(canonicalWorkspaceRoot));
    const resolvedPath = node_path_1.default.resolve(canonicalRoot, candidateRaw);
    const canonicalCandidate = await resolveExistingPath(resolvedPath);
    const normalizedCandidate = normalizePathForComparison(canonicalCandidate);
    const rootWithSep = canonicalRoot.endsWith(node_path_1.default.sep) ? canonicalRoot : `${canonicalRoot}${node_path_1.default.sep}`;
    if (normalizedCandidate !== canonicalRoot && !normalizedCandidate.startsWith(rootWithSep)) {
        throw Object.assign(new Error("Path is outside workspace"), {
            code: "PATH_OUTSIDE_WORKSPACE",
        });
    }
    return canonicalCandidate;
}
