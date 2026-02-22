/* eslint-disable no-console */

const fs = require("fs/promises");
const path = require("path");
const os = require("os");

const DEFAULT_OPENCLAW_SKILLS_DIR = path.join(os.homedir(), ".openclaw", "skills");
const DEFAULT_CODEX_SKILLS_DIR = path.join(os.homedir(), ".codex", "skills");
const DEFAULT_REPO_SKILLS_DIR = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/skills";

function parsePositiveInt(value, fallback, max = 100) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, max);
}

function normalizeSource(sourceRaw) {
  const source = String(sourceRaw || "both").trim().toLowerCase();
  if (source === "both" || source === "all") {
    return ["openclaw", "codex"];
  }
  if (source === "openclaw" || source === "codex" || source === "repo") {
    return [source];
  }
  throw new Error("source must be one of: both, openclaw, codex, repo");
}

function resolveSourceRoots() {
  return {
    openclaw: String(process.env.OPENCLAW_SKILLS_DIR || DEFAULT_OPENCLAW_SKILLS_DIR).trim(),
    codex: String(process.env.CODEX_SKILLS_DIR || DEFAULT_CODEX_SKILLS_DIR).trim(),
    repo: String(process.env.OPENCLAW_REPO_SKILLS_DIR || DEFAULT_REPO_SKILLS_DIR).trim(),
  };
}

async function directoryEntries(rootDir) {
  try {
    const entries = await fs.readdir(rootDir, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
      .map((entry) => entry.name)
      .sort((a, b) => a.localeCompare(b));
  } catch {
    return [];
  }
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function parseJsonSafe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function extractFrontmatterDescription(markdownText) {
  if (!markdownText.startsWith("---\n")) {
    return null;
  }

  const endIndex = markdownText.indexOf("\n---\n", 4);
  if (endIndex < 0) {
    return null;
  }

  const frontmatter = markdownText.slice(4, endIndex);
  for (const line of frontmatter.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.toLowerCase().startsWith("description:")) {
      continue;
    }
    const value = trimmed.slice("description:".length).trim();
    return value.replace(/^['\"]|['\"]$/g, "") || null;
  }

  return null;
}

async function readTextSafe(filePath) {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

async function buildSkillRecord(source, sourceRoot, skillName, includeSearchText = false) {
  const skillDir = path.join(sourceRoot, skillName);
  const toolsPath = path.join(skillDir, "tools.js");
  const metaPath = path.join(skillDir, "_meta.json");
  const skillPath = path.join(skillDir, "SKILL.md");

  const [hasTools, hasMeta, hasSkillMd] = await Promise.all([
    fileExists(toolsPath),
    fileExists(metaPath),
    fileExists(skillPath),
  ]);

  const [metaText, skillText] = await Promise.all([
    hasMeta ? readTextSafe(metaPath) : Promise.resolve(""),
    hasSkillMd ? readTextSafe(skillPath) : Promise.resolve(""),
  ]);

  const metadata = metaText ? parseJsonSafe(metaText) : null;
  const description = extractFrontmatterDescription(skillText);

  const record = {
    source,
    source_root: sourceRoot,
    skill: skillName,
    path: skillDir,
    has_tools_js: hasTools,
    has_meta_json: hasMeta,
    has_skill_md: hasSkillMd,
    description,
    metadata,
  };

  if (includeSearchText) {
    record.search_text = `${skillName}\n${description || ""}\n${skillText}`.toLowerCase();
  }

  return record;
}

async function collectSkills(sources, includeSearchText = false) {
  const sourceRoots = resolveSourceRoots();
  const skills = [];

  for (const source of sources) {
    const root = sourceRoots[source];
    const names = await directoryEntries(root);
    for (const name of names) {
      skills.push(await buildSkillRecord(source, root, name, includeSearchText));
    }
  }

  return {
    source_roots: sourceRoots,
    skills,
  };
}

function trimSearchFields(skillRecord) {
  const next = { ...skillRecord };
  delete next.search_text;
  return next;
}

async function find_skills_list_installed(args = {}) {
  const sources = normalizeSource(args.source);
  const includeWithoutTools = String(args.include_without_tools ?? "false").trim().toLowerCase() === "true";

  const { source_roots: sourceRoots, skills } = await collectSkills(sources, false);
  const filtered = includeWithoutTools ? skills : skills.filter((skill) => skill.has_tools_js);

  return {
    ok: true,
    requested_source: args.source || "both",
    source_roots: sourceRoots,
    count: filtered.length,
    skills: filtered.map(trimSearchFields),
  };
}

async function find_skills_search(args = {}) {
  const query = String(args.query || "").trim();
  if (!query) {
    throw new Error("query is required");
  }

  const sources = normalizeSource(args.source);
  const limit = parsePositiveInt(args.limit, 15, 100);
  const includeWithoutTools = String(args.include_without_tools ?? "true").trim().toLowerCase() === "true";

  const { source_roots: sourceRoots, skills } = await collectSkills(sources, true);
  const queryLower = query.toLowerCase();

  const matches = skills
    .filter((skill) => (includeWithoutTools ? true : skill.has_tools_js))
    .filter((skill) => String(skill.search_text || "").includes(queryLower))
    .slice(0, limit)
    .map(trimSearchFields);

  return {
    ok: true,
    query,
    requested_source: args.source || "both",
    source_roots: sourceRoots,
    count: matches.length,
    matches,
  };
}

async function find_skills_describe(args = {}) {
  const skillName = String(args.skill || args.name || "").trim();
  if (!skillName) {
    throw new Error("skill is required");
  }

  const sources = normalizeSource(args.source);
  const { source_roots: sourceRoots, skills } = await collectSkills(sources, false);

  const matches = skills.filter((record) => record.skill === skillName).map(trimSearchFields);
  if (!matches.length) {
    return {
      ok: false,
      requested_source: args.source || "both",
      source_roots: sourceRoots,
      error: `Skill not found: ${skillName}`,
    };
  }

  return {
    ok: true,
    requested_source: args.source || "both",
    source_roots: sourceRoots,
    skill: skillName,
    matches,
  };
}

module.exports = {
  find_skills_list_installed,
  find_skills_search,
  find_skills_describe,
};
