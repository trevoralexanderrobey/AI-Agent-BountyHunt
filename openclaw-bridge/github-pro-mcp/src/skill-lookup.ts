/**
 * ClawHub skill lookup — reads skills from ~/.openclaw/skills/ directory.
 * Provides listing, info retrieval, and dynamic tool execution with cache-busting.
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const DEFAULT_SKILLS_DIR = path.join(os.homedir(), ".openclaw", "skills");

function getSkillsDir(): string {
  return (process.env.OPENCLAW_SKILLS_DIR || "").trim() || DEFAULT_SKILLS_DIR;
}

export interface SkillSummary {
  name: string;
  hasSkillMd: boolean;
  hasToolsJs: boolean;
  toolNames: string[];
}

export interface SkillInfo {
  name: string;
  skillMd: string;
}

export async function listSkills(): Promise<SkillSummary[]> {
  const skillsDir = getSkillsDir();
  let entries: string[];
  try {
    entries = await fs.readdir(skillsDir);
  } catch {
    return [];
  }

  const skills: SkillSummary[] = [];
  for (const entry of entries) {
    const entryPath = path.join(skillsDir, entry);
    const stat = await fs.stat(entryPath).catch(() => null);
    if (!stat?.isDirectory()) continue;

    const hasSkillMd = await fs.access(path.join(entryPath, "SKILL.md")).then(() => true).catch(() => false);
    const hasToolsJs = await fs.access(path.join(entryPath, "tools.js")).then(() => true).catch(() => false);

    let toolNames: string[] = [];
    if (hasToolsJs) {
      try {
        toolNames = getToolNames(path.join(entryPath, "tools.js"));
      } catch {
        // tools.js exists but failed to load
      }
    }

    skills.push({ name: entry, hasSkillMd, hasToolsJs, toolNames });
  }

  return skills;
}

export async function getSkillInfo(skillName: string): Promise<SkillInfo> {
  validateSkillName(skillName);
  const skillMdPath = path.join(getSkillsDir(), skillName, "SKILL.md");
  const skillMd = await fs.readFile(skillMdPath, "utf-8");
  return { name: skillName, skillMd };
}

export function getToolNames(toolsJsPath: string): string[] {
  // Cache-bust to pick up edits without restart
  const resolved = require.resolve(toolsJsPath);
  delete require.cache[resolved];
  const mod = require(resolved) as Record<string, unknown>;
  return Object.keys(mod).filter((key) => typeof mod[key] === "function");
}

export async function executeSkillTool(
  skillName: string,
  toolName: string,
  args: Record<string, unknown>
): Promise<unknown> {
  validateSkillName(skillName);
  const toolsPath = path.join(getSkillsDir(), skillName, "tools.js");
  await fs.access(toolsPath); // throws if missing

  const resolved = require.resolve(toolsPath);
  delete require.cache[resolved];
  const mod = require(resolved) as Record<string, unknown>;
  const fn = mod[toolName];
  if (typeof fn !== "function") {
    throw new Error(`Tool "${toolName}" not found in skill "${skillName}". Available: ${Object.keys(mod).filter((k) => typeof mod[k] === "function").join(", ")}`);
  }

  return (fn as (args: Record<string, unknown>) => Promise<unknown>)(args);
}

function validateSkillName(name: string): void {
  if (!name || !/^[a-z0-9][a-z0-9_-]*$/i.test(name)) {
    throw new Error(`Invalid skill name: "${name}". Expected /[a-z0-9][a-z0-9_-]*/`);
  }
}
