/**
 * ClawHub skill tools — list skills, get skill info, and execute skill tools from ~/.openclaw/skills/.
 */

import { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { executeSkillTool, getSkillInfo, listSkills } from "../skill-lookup";

export const skillTools: Tool[] = [
  {
    name: "skill_list",
    description:
      "List all available OpenClaw skills from the local ClawHub (~/.openclaw/skills/). " +
      "Shows each skill's name, whether it has a SKILL.md manifest, and its available tool functions.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "skill_info",
    description:
      "Get the full SKILL.md documentation for a specific OpenClaw skill. " +
      "Returns the skill manifest including purpose, tools, safety constraints, and usage examples.",
    inputSchema: {
      type: "object" as const,
      properties: {
        skill: {
          type: "string",
          description: "Skill name (e.g., bounty-hunter, burp-suite, hackerone-researcher).",
        },
      },
      required: ["skill"],
    },
  },
  {
    name: "execute_skill_tool",
    description:
      "Execute a tool function from a specific OpenClaw skill. " +
      "Dynamically loads the skill's tools.js and calls the named function with the provided arguments. " +
      "Subject to mutation guards (BOUNTY_HUNTER_ALLOW_MUTATIONS, H1_ALLOW_MUTATIONS).",
    inputSchema: {
      type: "object" as const,
      properties: {
        skill: {
          type: "string",
          description: "Skill name (e.g., bounty-hunter, burp-suite).",
        },
        tool: {
          type: "string",
          description: "Tool function name to call (e.g., git_clone, h1_sync_scope).",
        },
        args: {
          type: "object",
          description: "Arguments to pass to the tool function.",
          additionalProperties: true,
        },
      },
      required: ["skill", "tool"],
    },
  },
];

export async function handleSkillTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  if (name === "skill_list") {
    const skills = await listSkills();
    if (skills.length === 0) {
      return {
        content: [{ type: "text", text: "No skills found in ~/.openclaw/skills/" }],
      };
    }

    const lines = skills.map((s) => {
      const tools = s.toolNames.length > 0 ? s.toolNames.join(", ") : "(none)";
      return `**${s.name}** — SKILL.md: ${s.hasSkillMd ? "yes" : "no"} | tools.js: ${s.hasToolsJs ? "yes" : "no"} | tools: ${tools}`;
    });

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }

  if (name === "skill_info") {
    const skill = String(args.skill || "").trim();
    if (!skill) {
      return { content: [{ type: "text", text: "Error: skill name is required" }], isError: true };
    }

    try {
      const info = await getSkillInfo(skill);
      return { content: [{ type: "text", text: info.skillMd }] };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text", text: `Error reading skill info: ${msg}` }], isError: true };
    }
  }

  if (name === "execute_skill_tool") {
    const skill = String(args.skill || "").trim();
    const tool = String(args.tool || "").trim();
    if (!skill || !tool) {
      return { content: [{ type: "text", text: "Error: skill and tool are required" }], isError: true };
    }

    const toolArgs = (args.args && typeof args.args === "object" && !Array.isArray(args.args))
      ? args.args as Record<string, unknown>
      : {};

    try {
      const result = await executeSkillTool(skill, tool, toolArgs);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text", text: `Error executing ${skill}/${tool}: ${msg}` }], isError: true };
    }
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
}
