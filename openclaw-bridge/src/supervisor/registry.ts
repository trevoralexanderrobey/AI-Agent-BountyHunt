export type ExecutionRole = "supervisor" | "internal" | "admin";
export type MutationClass = "read" | "write" | "exec" | "security";
export type LoggingLevel = "info" | "warn" | "error";

export interface SupervisorRegistryEntry {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  mutationClass: MutationClass;
  loggingLevel: LoggingLevel;
  roles: ExecutionRole[];
  workspacePathArgs?: string[];
}

// Canonical supervisor tool allowlist.
export const SUPERVISOR_TOOL_REGISTRY: SupervisorRegistryEntry[] = [
  {
    name: "supervisor.read_file",
    description: "Read a file from the configured workspace.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", minLength: 1, maxLength: 4096 },
      },
      required: ["path"],
      additionalProperties: false,
    },
    mutationClass: "read",
    loggingLevel: "info",
    roles: ["supervisor", "internal", "admin"],
    workspacePathArgs: ["path"],
  },
  {
    name: "supervisor.write_file",
    description: "Write UTF-8 content to a workspace file.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", minLength: 1, maxLength: 4096 },
        content: { type: "string", maxLength: 1_048_576 },
        createParents: { type: "boolean" },
      },
      required: ["path", "content"],
      additionalProperties: false,
    },
    mutationClass: "write",
    loggingLevel: "info",
    roles: ["supervisor", "internal", "admin"],
    workspacePathArgs: ["path"],
  },
  {
    name: "supervisor.apply_patch",
    description: "Apply a unified patch to the workspace.",
    inputSchema: {
      type: "object",
      properties: {
        patch: { type: "string", minLength: 1, maxLength: 262_144 },
      },
      required: ["patch"],
      additionalProperties: false,
    },
    mutationClass: "write",
    loggingLevel: "warn",
    roles: ["supervisor", "internal", "admin"],
  },
  {
    name: "supervisor.git_status",
    description: "Get git working tree status.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    mutationClass: "read",
    loggingLevel: "info",
    roles: ["supervisor", "internal", "admin"],
  },
  {
    name: "supervisor.git_commit",
    description: "Create a git commit from staged/working changes.",
    inputSchema: {
      type: "object",
      properties: {
        message: { type: "string", minLength: 1, maxLength: 200 },
        addAll: { type: "boolean" },
      },
      required: ["message"],
      additionalProperties: false,
    },
    mutationClass: "write",
    loggingLevel: "warn",
    roles: ["supervisor", "internal", "admin"],
  },
  {
    name: "supervisor.search",
    description: "Search workspace text with ripgrep.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string", minLength: 1, maxLength: 256 },
        path: { type: "string", minLength: 1, maxLength: 4096 },
        maxResults: { type: "number", minimum: 1, maximum: 500 },
      },
      required: ["pattern"],
      additionalProperties: false,
    },
    mutationClass: "read",
    loggingLevel: "info",
    roles: ["supervisor", "internal", "admin"],
    workspacePathArgs: ["path"],
  },
  {
    name: "supervisor.run_tests",
    description: "Run repository tests.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", enum: ["npm", "pnpm", "yarn", "bun"] },
        args: {
          type: "array",
          maxItems: 20,
          items: { type: "string", minLength: 1, maxLength: 200 },
        },
      },
      additionalProperties: false,
    },
    mutationClass: "exec",
    loggingLevel: "warn",
    roles: ["supervisor", "internal", "admin"],
  },
  {
    name: "supervisor.run_lint",
    description: "Run repository lint checks.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", enum: ["npm", "pnpm", "yarn", "bun"] },
        args: {
          type: "array",
          maxItems: 20,
          items: { type: "string", minLength: 1, maxLength: 200 },
        },
      },
      additionalProperties: false,
    },
    mutationClass: "exec",
    loggingLevel: "warn",
    roles: ["supervisor", "internal", "admin"],
  },
  {
    name: "supervisor.security_audit",
    description: "Run deployment/security audit checks.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    mutationClass: "security",
    loggingLevel: "warn",
    roles: ["supervisor", "internal", "admin"],
  },
];
