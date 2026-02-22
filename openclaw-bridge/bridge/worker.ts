import fs from "node:fs/promises";
import path from "node:path";
import { OpenClawClient } from "./openclaw-client";
import { executeRepositoryWorkflow, JobCancelledError } from "./repo-executor";
import { StateStore } from "./state-store";
import { JobRecord } from "./types";

interface LogEntry {
  timestamp: string;
  level: "info" | "warn" | "error";
  step: string;
  message: string;
  data?: unknown;
}

interface WorkerOptions {
  store: StateStore;
  openclawClient: OpenClawClient;
}

function nowIso(): string {
  return new Date().toISOString();
}

async function appendLog(logPath: string, entry: LogEntry): Promise<void> {
  const line = `${JSON.stringify(entry)}\n`;
  await fs.appendFile(logPath, line, "utf-8");
}

function summarizeInstruction(instruction: string): string {
  const cleaned = instruction.replace(/\s+/g, " ").trim();
  return cleaned.length > 140 ? `${cleaned.slice(0, 137)}...` : cleaned;
}

function buildSuccessReport(job: JobRecord, openclawText: string | undefined, details: {
  repoPath?: string;
  branchName?: string;
  changedFiles: string[];
  testSummary: string;
  commitSha?: string;
  pushSucceeded: boolean;
  prUrl?: string;
}): string {
  return [
    `# Mission Report: ${job.id}`,
    "",
    `- Status: succeeded`,
    `- Created: ${job.created_at}`,
    `- Finished: ${nowIso()}`,
    `- Requester: ${job.request.requester}`,
    `- Workspace: ${job.workspace_path}`,
    `- Repo URL: ${job.request.repo_url || "(none)"}`,
    `- Repo Path: ${details.repoPath || "(none)"}`,
    `- Branch: ${details.branchName || "(none)"}`,
    `- Commit SHA: ${details.commitSha || "(none)"}`,
    `- Push Succeeded: ${details.pushSucceeded ? "yes" : "no"}`,
    `- PR URL: ${details.prUrl || "(none)"}`,
    "",
    "## Instruction",
    "",
    job.request.instruction,
    "",
    "## Context URLs",
    "",
    ...(job.request.context_urls && job.request.context_urls.length > 0 ? job.request.context_urls.map((url) => `- ${url}`) : ["- (none)"]),
    "",
    "## Hints",
    "",
    job.request.hints || "(none)",
    "",
    "## Changed Files",
    "",
    ...(details.changedFiles.length > 0 ? details.changedFiles.map((filePath) => `- ${filePath}`) : ["- (none detected)"]),
    "",
    "## Test Summary",
    "",
    details.testSummary,
    "",
    "## OpenClaw Response",
    "",
    openclawText || "(none)",
  ].join("\n");
}

function buildFailureReport(job: JobRecord, errorMessage: string): string {
  return [
    `# Mission Report: ${job.id}`,
    "",
    `- Status: failed`,
    `- Created: ${job.created_at}`,
    `- Finished: ${nowIso()}`,
    `- Requester: ${job.request.requester}`,
    `- Workspace: ${job.workspace_path}`,
    `- Repo URL: ${job.request.repo_url || "(none)"}`,
    "",
    "## Instruction",
    "",
    job.request.instruction,
    "",
    "## Error",
    "",
    errorMessage,
  ].join("\n");
}

export class JobWorker {
  private readonly store: StateStore;
  private readonly openclawClient: OpenClawClient;
  private readonly queue: string[] = [];
  private processing = false;

  constructor(options: WorkerOptions) {
    this.store = options.store;
    this.openclawClient = options.openclawClient;
  }

  enqueue(jobId: string): void {
    if (!this.queue.includes(jobId)) {
      this.queue.push(jobId);
    }

    void this.processLoop();
  }

  enqueueQueuedJobs(): void {
    for (const jobId of this.store.listQueuedJobIds()) {
      this.enqueue(jobId);
    }
  }

  private async processLoop(): Promise<void> {
    if (this.processing) {
      return;
    }

    this.processing = true;

    try {
      while (this.queue.length > 0) {
        const jobId = this.queue.shift();
        if (!jobId) {
          continue;
        }

        await this.processJob(jobId);
      }
    } finally {
      this.processing = false;
    }
  }

  private async processJob(jobId: string): Promise<void> {
    const existing = this.store.getJob(jobId);
    if (!existing) {
      return;
    }

    if (existing.status === "cancelled") {
      return;
    }

    const job = await this.store.updateStatus(jobId, "running", {
      summary: summarizeInstruction(existing.request.instruction),
      error_message: undefined,
    });

    const missionInputPath = path.join(job.workspace_path, "MISSION_INPUT.json");
    const missionLogPath = path.join(job.workspace_path, "MISSION_LOG.ndjson");
    const missionReportPath = path.join(job.workspace_path, "MISSION_REPORT.md");

    await fs.mkdir(job.workspace_path, { recursive: true });
    await fs.writeFile(
      missionInputPath,
      JSON.stringify(
        {
          job_id: job.id,
          request: job.request,
          created_at: job.created_at,
          started_at: job.started_at,
        },
        null,
        2
      ),
      "utf-8"
    );

    const logger = async (entry: { level: "info" | "warn" | "error"; step: string; message: string; data?: unknown }) => {
      await appendLog(missionLogPath, {
        timestamp: nowIso(),
        ...entry,
      });
    };

    const isCancelled = async () => {
      const current = this.store.getJob(jobId);
      return current?.status === "cancelled";
    };

    try {
      await logger({ level: "info", step: "job.start", message: `Processing ${job.id}` });

      const result = await executeRepositoryWorkflow({
        jobId,
        submission: job.request,
        workspacePath: job.workspace_path,
        openclawClient: this.openclawClient,
        logger,
        isCancelled,
      });

      const summary = `Completed ${job.id}. ${result.changedFiles.length} changed file(s). ${result.testSummary}`;
      const report = buildSuccessReport(job, result.openclawText, {
        repoPath: result.repoPath,
        branchName: result.branchName,
        changedFiles: result.changedFiles,
        testSummary: result.testSummary,
        commitSha: result.commitSha,
        pushSucceeded: result.pushSucceeded,
        prUrl: result.prUrl,
      });

      await fs.writeFile(missionReportPath, report, "utf-8");

      await this.store.updateStatus(job.id, "succeeded", {
        repo_path: result.repoPath,
        branch_name: result.branchName,
        pr_url: result.prUrl,
        summary,
      });

      await logger({
        level: "info",
        step: "job.finish",
        message: "Job succeeded",
        data: {
          pr_url: result.prUrl,
          branch: result.branchName,
          testSummary: result.testSummary,
        },
      });
    } catch (error) {
      if (error instanceof JobCancelledError) {
        await this.store.updateStatus(job.id, "cancelled", {
          error_message: error.message,
          summary: `Cancelled ${job.id}`,
        });

        await logger({
          level: "warn",
          step: "job.cancelled",
          message: error.message,
        });

        await fs.writeFile(
          missionReportPath,
          buildFailureReport(job, `Cancelled: ${error.message}`),
          "utf-8"
        );
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      await this.store.updateStatus(job.id, "failed", {
        error_message: message,
        summary: `Failed ${job.id}: ${message}`,
      });

      await logger({
        level: "error",
        step: "job.failed",
        message,
      });

      await fs.writeFile(missionReportPath, buildFailureReport(job, message), "utf-8");
    }
  }
}
