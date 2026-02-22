import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../repo-executor", () => {
  class MockJobCancelledError extends Error {
    constructor(message = "Job was cancelled") {
      super(message);
      this.name = "JobCancelledError";
    }
  }

  return {
    executeRepositoryWorkflow: vi.fn(),
    JobCancelledError: MockJobCancelledError,
  };
});

import { executeRepositoryWorkflow } from "../repo-executor";
import { StateStore } from "../state-store";
import { JobWorker } from "../worker";

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-bridge-worker-"));
  tempDirs.push(dir);
  return dir;
}

async function waitForStatus(store: StateStore, jobId: string, terminal: Array<"succeeded" | "failed" | "cancelled">) {
  const timeoutMs = 4000;
  const intervalMs = 50;
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    const job = store.getJob(jobId);
    if (job && terminal.includes(job.status as "succeeded" | "failed" | "cancelled")) {
      return job;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  throw new Error(`Timed out waiting for terminal status on ${jobId}`);
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
});

describe("worker integration", () => {
  it("writes mission report on successful execution", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    vi.mocked(executeRepositoryWorkflow).mockResolvedValueOnce({
      repoPath: path.join(root, "jobs", "repo"),
      branchName: "fix/job-1",
      testSummary: "npm test passed",
      changedFiles: ["src/index.ts"],
      commitSha: "abc123",
      pushSucceeded: true,
      prUrl: "https://github.com/openclaw/openclaw/pull/10",
      openclawText: "Implemented fix and validated tests.",
    });

    const worker = new JobWorker({
      store,
      openclawClient: {} as never,
    });

    const job = await store.createJob({
      instruction: "Fix memory leak in auth pipeline",
      requester: "cli",
      repo_url: "https://github.com/openclaw/openclaw",
    });

    worker.enqueue(job.id);

    const completed = await waitForStatus(store, job.id, ["succeeded", "failed"]);
    expect(completed.status).toBe("succeeded");

    const reportPath = path.join(job.workspace_path, "MISSION_REPORT.md");
    const report = await fs.readFile(reportPath, "utf-8");
    expect(report).toContain("Status: succeeded");
    expect(report).toContain("https://github.com/openclaw/openclaw/pull/10");
  });

  it("marks job failed when OpenClaw execution fails", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    vi.mocked(executeRepositoryWorkflow).mockRejectedValueOnce(new Error("OpenClaw API failed: gateway unavailable"));

    const worker = new JobWorker({
      store,
      openclawClient: {} as never,
    });

    const job = await store.createJob({
      instruction: "Implement issue fix",
      requester: "codex",
    });

    worker.enqueue(job.id);

    const completed = await waitForStatus(store, job.id, ["failed", "succeeded"]);
    expect(completed.status).toBe("failed");
    expect(completed.error_message).toContain("OpenClaw API failed");

    const reportPath = path.join(job.workspace_path, "MISSION_REPORT.md");
    const report = await fs.readFile(reportPath, "utf-8");
    expect(report).toContain("OpenClaw API failed");
  });

  it("surfaces clone/auth failures with actionable report text", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    vi.mocked(executeRepositoryWorkflow).mockRejectedValueOnce(
      new Error("git clone failed: access denied (private repository or missing SSH credentials)")
    );

    const worker = new JobWorker({
      store,
      openclawClient: {} as never,
    });

    const job = await store.createJob({
      instruction: "Fix private repo issue",
      requester: "cli",
      repo_url: "https://github.com/example/private-repo",
    });

    worker.enqueue(job.id);

    const completed = await waitForStatus(store, job.id, ["failed", "succeeded"]);
    expect(completed.status).toBe("failed");
    expect(completed.error_message).toContain("access denied");
  });

  it("records iterative test stabilization summaries", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    vi.mocked(executeRepositoryWorkflow).mockResolvedValueOnce({
      repoPath: path.join(root, "jobs", "repo"),
      branchName: "fix/job-iterative",
      testSummary: "npm test passed after 2 attempts",
      changedFiles: ["src/auth.ts", "src/auth.test.ts"],
      commitSha: "def456",
      pushSucceeded: true,
      prUrl: "https://github.com/org/repo/pull/402",
      openclawText: "First attempt failed tests, second attempt passed.",
    });

    const worker = new JobWorker({
      store,
      openclawClient: {} as never,
    });

    const job = await store.createJob({
      instruction: "Stabilize flaky auth tests",
      requester: "codex",
      repo_url: "https://github.com/org/repo",
    });

    worker.enqueue(job.id);

    const completed = await waitForStatus(store, job.id, ["succeeded", "failed"]);
    expect(completed.status).toBe("succeeded");

    const reportPath = path.join(job.workspace_path, "MISSION_REPORT.md");
    const report = await fs.readFile(reportPath, "utf-8");
    expect(report).toContain("passed after 2 attempts");
  });
});
