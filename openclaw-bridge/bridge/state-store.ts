import fs from "node:fs/promises";
import path from "node:path";
import { JobRecord, JobStatus, MissionReportIndex, TaskSubmission } from "./types";

interface PersistedState {
  jobs: JobRecord[];
}

const INDEX_FILE = "index.json";
const MISSION_INDEX_FILE = "MISSION_REPORT_INDEX.json";

function nowIso(): string {
  return new Date().toISOString();
}

function generateJobId(): string {
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const random = Math.random().toString(36).slice(2, 8);
  return `job-${timestamp}-${random}`;
}

async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return JSON.parse(content) as T;
  } catch {
    return fallback;
  }
}

async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
  const tmpPath = `${filePath}.tmp`;
  await fs.writeFile(tmpPath, JSON.stringify(value, null, 2), "utf-8");
  await fs.rename(tmpPath, filePath);
}

export class StateStore {
  private readonly workspaceRoot: string;
  private readonly jobsRoot: string;
  private readonly indexPath: string;
  private readonly missionIndexPath: string;
  private state: PersistedState = { jobs: [] };

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
    this.jobsRoot = path.join(workspaceRoot, "jobs");
    this.indexPath = path.join(this.jobsRoot, INDEX_FILE);
    this.missionIndexPath = path.join(this.jobsRoot, MISSION_INDEX_FILE);
  }

  async init(): Promise<void> {
    await fs.mkdir(this.jobsRoot, { recursive: true });
    this.state = await readJsonFile<PersistedState>(this.indexPath, { jobs: [] });

    for (const job of this.state.jobs) {
      if (job.status === "running") {
        job.status = "queued";
        job.updated_at = nowIso();
        job.error_message = "Recovered from restart while running; re-queued automatically.";
      }
    }

    await this.persist();
    await this.persistMissionIndex();
  }

  getWorkspaceRoot(): string {
    return this.workspaceRoot;
  }

  getJobsRoot(): string {
    return this.jobsRoot;
  }

  listJobs(): JobRecord[] {
    return [...this.state.jobs].sort((left, right) => right.created_at.localeCompare(left.created_at));
  }

  listQueuedJobIds(): string[] {
    return this.state.jobs.filter((job) => job.status === "queued").map((job) => job.id);
  }

  getJob(jobId: string): JobRecord | undefined {
    return this.state.jobs.find((job) => job.id === jobId);
  }

  async createJob(request: TaskSubmission): Promise<JobRecord> {
    const id = generateJobId();
    const timestamp = nowIso();
    const workspacePath = path.join(this.jobsRoot, id);

    const job: JobRecord = {
      id,
      status: "queued",
      request,
      created_at: timestamp,
      updated_at: timestamp,
      workspace_path: workspacePath,
    };

    await fs.mkdir(workspacePath, { recursive: true });
    this.state.jobs.unshift(job);
    await this.persist();
    await this.persistMissionIndex();
    return job;
  }

  async updateJob(jobId: string, updates: Partial<JobRecord>): Promise<JobRecord> {
    const job = this.getJob(jobId);
    if (!job) {
      throw new Error(`Job not found: ${jobId}`);
    }

    Object.assign(job, updates, { updated_at: nowIso() });
    await this.persist();
    await this.persistMissionIndex();
    return job;
  }

  async updateStatus(jobId: string, status: JobStatus, updates: Partial<JobRecord> = {}): Promise<JobRecord> {
    const timestamp = nowIso();
    const base: Partial<JobRecord> = {
      ...updates,
      status,
      updated_at: timestamp,
    };

    if (status === "running") {
      base.started_at = updates.started_at || timestamp;
    }

    if (status === "succeeded" || status === "failed" || status === "cancelled") {
      base.finished_at = updates.finished_at || timestamp;
    }

    return this.updateJob(jobId, base);
  }

  async persistMissionIndex(): Promise<MissionReportIndex> {
    const jobs = this.state.jobs.map((job) => ({
      id: job.id,
      status: job.status,
      created_at: job.created_at,
      workspace_path: job.workspace_path,
      report_path: path.join(job.workspace_path, "MISSION_REPORT.md"),
      pr_url: job.pr_url,
    }));

    const index: MissionReportIndex = {
      updated_at: nowIso(),
      jobs,
    };

    await writeJsonFile(this.missionIndexPath, index);
    return index;
  }

  private async persist(): Promise<void> {
    await writeJsonFile(this.indexPath, this.state);
  }
}
