/* eslint-disable no-console */

const fs = require("fs/promises");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const DEFAULT_LEARNINGS_DIR = path.join(os.homedir(), ".openclaw", "workspace", ".learnings");

function normalizePriority(priorityRaw, fallback = "medium") {
  const value = String(priorityRaw || fallback).trim().toLowerCase();
  return ["low", "medium", "high", "critical"].includes(value) ? value : fallback;
}

function normalizeArea(areaRaw, fallback = "docs") {
  const value = String(areaRaw || fallback).trim().toLowerCase();
  return value || fallback;
}

function normalizeStatus(statusRaw, fallback = "pending") {
  const value = String(statusRaw || fallback).trim().toLowerCase();
  return value || fallback;
}

function normalizeSource(sourceRaw, fallback = "bridge_tool") {
  const value = String(sourceRaw || fallback).trim();
  return value || fallback;
}

function asCsv(input, fallback = "none") {
  if (Array.isArray(input)) {
    const joined = input
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .join(", ");
    return joined || fallback;
  }

  const value = String(input || "").trim();
  return value || fallback;
}

function getLearningsDir() {
  return String(process.env.SELF_IMPROVEMENT_LEARNINGS_DIR || DEFAULT_LEARNINGS_DIR).trim();
}

function targetFile(fileKey) {
  const map = {
    learning: "LEARNINGS.md",
    error: "ERRORS.md",
    feature: "FEATURE_REQUESTS.md",
  };

  const fileName = map[fileKey];
  if (!fileName) {
    throw new Error(`Unsupported file key: ${fileKey}`);
  }

  return path.join(getLearningsDir(), fileName);
}

async function ensureLearningFile(filePath, title) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  try {
    await fs.access(filePath);
  } catch {
    await fs.writeFile(filePath, `# ${title}\n\n`, "utf8");
  }
}

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix) {
  const now = new Date();
  const y = String(now.getUTCFullYear());
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const suffix = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `${prefix}-${y}${m}${d}-${suffix}`;
}

async function appendEntry(fileKey, title, entry) {
  const filePath = targetFile(fileKey);
  await ensureLearningFile(filePath, title);
  await fs.appendFile(filePath, entry, "utf8");
  return filePath;
}

function buildLearningEntry(args = {}) {
  const id = makeId("LRN");
  const logged = nowIso();
  const category = String(args.category || "best_practice").trim();
  const summary = String(args.summary || "Learning captured via bridge tool").trim();
  const details = String(args.details || args.context || "No details provided.").trim();
  const suggestedAction = String(args.suggested_action || "Review and promote if broadly applicable.").trim();

  return {
    id,
    logged,
    entry: [
      `## [${id}] ${category}`,
      "",
      `**Logged**: ${logged}`,
      `**Priority**: ${normalizePriority(args.priority, "medium")}`,
      `**Status**: ${normalizeStatus(args.status, "pending")}`,
      `**Area**: ${normalizeArea(args.area, "docs")}`,
      "",
      "### Summary",
      summary,
      "",
      "### Details",
      details,
      "",
      "### Suggested Action",
      suggestedAction,
      "",
      "### Metadata",
      `- Source: ${normalizeSource(args.source, "bridge_tool")}`,
      `- Related Files: ${asCsv(args.related_files, "none")}`,
      `- Tags: ${asCsv(args.tags, "learning")}`,
      "",
      "---",
      "",
    ].join("\n"),
  };
}

function buildErrorEntry(args = {}) {
  const id = makeId("ERR");
  const logged = nowIso();
  const summary = String(args.summary || "Error captured via bridge tool").trim();
  const errorText = String(args.error || args.error_message || "No error text provided.").trim();
  const context = String(args.context || "No additional context provided.").trim();
  const suggestedFix = String(args.suggested_fix || "Reproduce and identify root cause.").trim();

  return {
    id,
    logged,
    entry: [
      `## [${id}] ${String(args.component || "bridge").trim()}`,
      "",
      `**Logged**: ${logged}`,
      `**Priority**: ${normalizePriority(args.priority, "high")}`,
      `**Status**: ${normalizeStatus(args.status, "pending")}`,
      `**Area**: ${normalizeArea(args.area, "infra")}`,
      "",
      "### Summary",
      summary,
      "",
      "### Error",
      "```",
      errorText,
      "```",
      "",
      "### Context",
      context,
      "",
      "### Suggested Fix",
      suggestedFix,
      "",
      "### Metadata",
      `- Reproducible: ${String(args.reproducible || "unknown").trim() || "unknown"}`,
      `- Related Files: ${asCsv(args.related_files, "none")}`,
      "",
      "---",
      "",
    ].join("\n"),
  };
}

function buildFeatureEntry(args = {}) {
  const id = makeId("FEAT");
  const logged = nowIso();
  const capability = String(args.requested_capability || args.capability || "unspecified_capability").trim();
  const userContext = String(args.user_context || args.context || "No user context provided.").trim();
  const complexity = String(args.complexity || "medium").trim().toLowerCase();
  const implementation = String(args.suggested_implementation || "Define requirements and scaffold implementation.").trim();

  return {
    id,
    logged,
    entry: [
      `## [${id}] ${capability}`,
      "",
      `**Logged**: ${logged}`,
      `**Priority**: ${normalizePriority(args.priority, "medium")}`,
      `**Status**: ${normalizeStatus(args.status, "pending")}`,
      `**Area**: ${normalizeArea(args.area, "config")}`,
      "",
      "### Requested Capability",
      capability,
      "",
      "### User Context",
      userContext,
      "",
      "### Complexity Estimate",
      complexity,
      "",
      "### Suggested Implementation",
      implementation,
      "",
      "### Metadata",
      `- Frequency: ${String(args.frequency || "first_time").trim() || "first_time"}`,
      `- Related Features: ${asCsv(args.related_features, "none")}`,
      "",
      "---",
      "",
    ].join("\n"),
  };
}

function parsePositiveInt(value, fallback, max = 100) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, max);
}

async function readRecentEntries(filePath) {
  let text;
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch {
    return [];
  }

  const matches = [...text.matchAll(/^## \[(.+?)\] (.+)$/gm)];
  return matches.map((match) => ({
    id: match[1],
    title: match[2],
    file: filePath,
  }));
}

async function self_improvement_log_learning(args = {}) {
  const payload = buildLearningEntry(args);
  const filePath = await appendEntry("learning", "Learnings", payload.entry);

  return {
    ok: true,
    type: "learning",
    id: payload.id,
    logged: payload.logged,
    file: filePath,
  };
}

async function self_improvement_log_error(args = {}) {
  const payload = buildErrorEntry(args);
  const filePath = await appendEntry("error", "Errors", payload.entry);

  return {
    ok: true,
    type: "error",
    id: payload.id,
    logged: payload.logged,
    file: filePath,
  };
}

async function self_improvement_log_feature_request(args = {}) {
  const payload = buildFeatureEntry(args);
  const filePath = await appendEntry("feature", "Feature Requests", payload.entry);

  return {
    ok: true,
    type: "feature_request",
    id: payload.id,
    logged: payload.logged,
    file: filePath,
  };
}

async function self_improvement_recent(args = {}) {
  const limit = parsePositiveInt(args.limit, 10, 200);
  const files = [
    targetFile("learning"),
    targetFile("error"),
    targetFile("feature"),
  ];

  const grouped = await Promise.all(files.map((filePath) => readRecentEntries(filePath)));
  const entries = grouped.flat().slice(-limit).reverse();

  return {
    ok: true,
    learning_dir: getLearningsDir(),
    count: entries.length,
    entries,
  };
}

module.exports = {
  self_improvement_log_learning,
  self_improvement_log_error,
  self_improvement_log_feature_request,
  self_improvement_recent,
};
