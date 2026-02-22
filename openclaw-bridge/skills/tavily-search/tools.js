const path = require("node:path");
const fs = require("node:fs");
const { spawn } = require("node:child_process");

const DEFAULT_BRIDGE_ENV_FILE = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge/.env";

function readEnvVarFromFile(filePath, key) {
  if (!filePath || !fs.existsSync(filePath)) return "";
  const text = fs.readFileSync(filePath, "utf8");
  const line = text
    .split(/\r?\n/)
    .find((l) => l.trim().startsWith(`${key}=`) && !l.trim().startsWith(`#`));
  if (!line) return "";
  return line.slice(line.indexOf("=") + 1).trim().replace(/^['"]|['"]$/g, "");
}

function resolveTavilyApiKey() {
  const direct = String(process.env.TAVILY_API_KEY || "").trim();
  if (direct) return direct;

  const fromBridgeEnv = readEnvVarFromFile(
    process.env.OPENCLAW_BRIDGE_ENV_FILE || DEFAULT_BRIDGE_ENV_FILE,
    "TAVILY_API_KEY",
  );
  if (fromBridgeEnv) return fromBridgeEnv;

  return "";
}

function runScript(scriptName, args, extraEnv = {}) {
  const scriptPath = path.join(__dirname, "scripts", scriptName);

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      env: { ...process.env, ...extraEnv },
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (err) => {
      reject(err);
    });
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error((stderr || stdout || `script exited with code ${code}`).trim()));
        return;
      }
      resolve(stdout.trim());
    });
  });
}

function toPositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

async function tavily_search(args = {}) {
  const query = String(args.query || "").trim();
  if (!query) {
    throw new Error("tavily_search requires args.query");
  }
  const apiKey = resolveTavilyApiKey();
  if (!apiKey) {
    throw new Error("Missing TAVILY_API_KEY");
  }

  const n = toPositiveInt(args.n, 5);
  const deep = Boolean(args.deep);
  const topic = String(args.topic || "general").trim() || "general";
  const days = args.days == null ? null : toPositiveInt(args.days, 7);

  const scriptArgs = [query, "-n", String(n), "--topic", topic];
  if (deep) scriptArgs.push("--deep");
  if (topic === "news" && days != null) {
    scriptArgs.push("--days", String(days));
  }

  return runScript("search.mjs", scriptArgs, { TAVILY_API_KEY: apiKey });
}

async function tavily_extract(args = {}) {
  const url = String(args.url || "").trim();
  if (!url) {
    throw new Error("tavily_extract requires args.url");
  }
  const apiKey = resolveTavilyApiKey();
  if (!apiKey) {
    throw new Error("Missing TAVILY_API_KEY");
  }
  return runScript("extract.mjs", [url], { TAVILY_API_KEY: apiKey });
}

module.exports = {
  tavily_search,
  tavily_extract,
};
