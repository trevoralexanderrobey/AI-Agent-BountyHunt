import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { OpenClawClient } from "./openclaw-client";
import { RepoExecutionResult, TaskSubmission } from "./types";

const execFileAsync = promisify(execFile);

interface LogEntry {
  level: "info" | "warn" | "error";
  step: string;
  message: string;
  data?: unknown;
}

interface RepoExecutorInput {
  jobId: string;
  submission: TaskSubmission;
  workspacePath: string;
  openclawClient: OpenClawClient;
  logger: (entry: LogEntry) => Promise<void>;
  isCancelled: () => Promise<boolean>;
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

class JobCancelledError extends Error {
  constructor(message = "Job was cancelled") {
    super(message);
    this.name = "JobCancelledError";
  }
}

function parseChangedFiles(statusOutput: string): string[] {
  return statusOutput
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.replace(/^[A-Z?]{1,2}\s+/, "").trim())
    .filter(Boolean);
}

function makeCommitTitle(instruction: string, jobId: string): string {
  const fallback = `fix: resolve task ${jobId}`;
  const cleaned = instruction.replace(/\s+/g, " ").trim();
  if (!cleaned) {
    return fallback;
  }

  const maxLength = 70;
  const clipped = cleaned.length > maxLength ? `${cleaned.slice(0, maxLength - 3)}...` : cleaned;
  return `fix: ${clipped}`;
}

function detectTestCommand(repoPath: string): [string, string[]] | null {
  if (existsSync(path.join(repoPath, "package.json"))) {
    return ["npm", ["test", "--", "--runInBand"]];
  }

  if (existsSync(path.join(repoPath, "pnpm-lock.yaml"))) {
    return ["pnpm", ["test"]];
  }

  if (existsSync(path.join(repoPath, "pyproject.toml")) || existsSync(path.join(repoPath, "requirements.txt"))) {
    return ["pytest", []];
  }

  if (existsSync(path.join(repoPath, "Cargo.toml"))) {
    return ["cargo", ["test"]];
  }

  return null;
}

async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  logger: (entry: LogEntry) => Promise<void>,
  step: string,
  allowFailure = false
): Promise<CommandResult> {
  await logger({
    level: "info",
    step,
    message: `Running command: ${command} ${args.join(" ")}`,
  });

  try {
    const result = await execFileAsync(command, args, {
      cwd,
      env: process.env,
      maxBuffer: 32 * 1024 * 1024,
    });

    const stdout = String(result.stdout || "");
    const stderr = String(result.stderr || "");

    await logger({
      level: "info",
      step,
      message: "Command completed",
      data: { stdout, stderr },
    });

    return { stdout, stderr, exitCode: 0 };
  } catch (error) {
    const processError = error as { stdout?: string; stderr?: string; code?: number; message?: string };
    const stdout = String(processError.stdout || "");
    const stderr = String(processError.stderr || processError.message || "");
    const exitCode = Number(processError.code || 1);

    await logger({
      level: allowFailure ? "warn" : "error",
      step,
      message: "Command failed",
      data: { stdout, stderr, exitCode },
    });

    if (!allowFailure) {
      throw new Error(`${command} ${args.join(" ")} failed: ${stderr || stdout}`);
    }

    return { stdout, stderr, exitCode };
  }
}

async function ensureRepoAvailable(input: RepoExecutorInput, repoPath: string): Promise<void> {
  const { submission, logger } = input;

  if (!submission.repo_url) {
    return;
  }

  if (existsSync(path.join(repoPath, ".git"))) {
    await runCommand("git", ["remote", "set-url", "origin", submission.repo_url], repoPath, logger, "repo.remote");
    await runCommand("git", ["fetch", "origin", "--prune"], repoPath, logger, "repo.fetch");

    const checkoutMain = await runCommand("git", ["checkout", "main"], repoPath, logger, "repo.checkout.main", true);
    if (checkoutMain.exitCode !== 0) {
      const checkoutMaster = await runCommand("git", ["checkout", "master"], repoPath, logger, "repo.checkout.master", true);
      if (checkoutMaster.exitCode !== 0) {
        await runCommand("git", ["checkout", "trunk"], repoPath, logger, "repo.checkout.trunk", true);
      }
    }

    await runCommand("git", ["pull", "--ff-only"], repoPath, logger, "repo.pull", true);
    return;
  }

  await fs.mkdir(path.dirname(repoPath), { recursive: true });
  await runCommand("git", ["clone", submission.repo_url, repoPath], path.dirname(repoPath), logger, "repo.clone");
}

function extractFirstPrUrl(value: string): string | undefined {
  const match = value.match(/https:\/\/github\.com\/[^\s]+\/pull\/\d+/);
  return match ? match[0] : undefined;
}

async function commandExists(name: string): Promise<boolean> {
  try {
    await execFileAsync("which", [name]);
    return true;
  } catch {
    return false;
  }
}

export async function executeRepositoryWorkflow(input: RepoExecutorInput): Promise<RepoExecutionResult> {
  const { jobId, submission, workspacePath, logger, isCancelled, openclawClient } = input;

  if (await isCancelled()) {
    throw new JobCancelledError();
  }

  const repoPath = path.join(workspacePath, "repo");
  let branchName: string | undefined = submission.branch_name?.trim() || `fix/job-${jobId}`;
  let testSummary = "No tests executed";
  let changedFiles: string[] = [];
  let commitSha: string | undefined;
  let pushSucceeded = false;
  let prUrl: string | undefined;

  if (submission.repo_url) {
    await ensureRepoAvailable(input, repoPath);

    if (await isCancelled()) {
      throw new JobCancelledError();
    }

    await runCommand("git", ["checkout", "-B", branchName], repoPath, logger, "git.checkout-branch");
  } else {
    branchName = submission.branch_name?.trim();
  }

  const openclawResult = await openclawClient.runTask({
    jobId,
    submission,
    repoPath: submission.repo_url ? repoPath : undefined,
    workspacePath,
  });

  await logger({
    level: "info",
    step: "openclaw.run",
    message: "OpenClaw returned response",
    data: {
      model: openclawResult.model,
      textPreview: openclawResult.text.slice(0, 8000),
    },
  });

  if (submission.repo_url) {
    const statusResult = await runCommand("git", ["status", "--porcelain"], repoPath, logger, "git.status", true);
    changedFiles = parseChangedFiles(statusResult.stdout);

    const detectedTestCommand = detectTestCommand(repoPath);
    if (detectedTestCommand) {
      const [testCommand, testArgs] = detectedTestCommand;
      const testResult = await runCommand(testCommand, testArgs, repoPath, logger, "tests.run", true);
      if (testResult.exitCode === 0) {
        testSummary = `${testCommand} ${testArgs.join(" ")} passed`;
      } else {
        testSummary = `${testCommand} ${testArgs.join(" ")} failed with exit code ${testResult.exitCode}`;
      }
    }

    if (changedFiles.length > 0) {
      await runCommand("git", ["add", "-A"], repoPath, logger, "git.add");

      const commitTitle = makeCommitTitle(submission.instruction, jobId);
      await runCommand("git", ["commit", "-m", commitTitle], repoPath, logger, "git.commit", true);

      const shaResult = await runCommand("git", ["rev-parse", "HEAD"], repoPath, logger, "git.rev-parse", true);
      commitSha = shaResult.stdout.trim() || undefined;

      const pushResult = await runCommand(
        "git",
        ["push", "-u", "origin", branchName || `fix/job-${jobId}`],
        repoPath,
        logger,
        "git.push",
        true
      );
      pushSucceeded = pushResult.exitCode === 0;

      if (pushSucceeded && (await commandExists("gh"))) {
        const title = makeCommitTitle(submission.instruction, jobId).replace(/^fix:\s*/i, "");
        const body = [
          "Automated draft PR created by OpenClaw Bounty Bridge.",
          "",
          `Job ID: ${jobId}`,
          `Instruction: ${submission.instruction}`,
          "",
          "Please review and adjust before marking ready for review.",
        ].join("\n");

        const prResult = await runCommand(
          "gh",
          ["pr", "create", "--draft", "--title", title || `Task ${jobId}`, "--body", body],
          repoPath,
          logger,
          "gh.pr.create",
          true
        );

        prUrl = extractFirstPrUrl(`${prResult.stdout}\n${prResult.stderr}`);
      }
    }
  }

  return {
    repoPath: submission.repo_url ? repoPath : undefined,
    branchName,
    testSummary,
    changedFiles,
    commitSha,
    pushSucceeded,
    prUrl,
    openclawText: openclawResult.text,
  };
}

export { JobCancelledError };
