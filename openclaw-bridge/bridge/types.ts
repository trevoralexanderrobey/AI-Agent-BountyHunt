export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface TaskSubmission {
  instruction: string;
  repo_url?: string;
  context_urls?: string[];
  gateway_base_url?: string;
  auth_token?: string;
  hints?: string;
  branch_name?: string;
  requester: string;
  model?: string;
}

export interface JobRecord {
  id: string;
  status: JobStatus;
  request: TaskSubmission;
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
  workspace_path: string;
  repo_path?: string;
  branch_name?: string;
  pr_url?: string;
  error_message?: string;
  summary?: string;
}

export interface MissionReportIndex {
  updated_at: string;
  jobs: Array<{
    id: string;
    status: JobStatus;
    created_at: string;
    workspace_path: string;
    report_path: string;
    pr_url?: string;
  }>;
}

export interface OpenClawResult {
  model: string;
  text: string;
  raw: unknown;
}

export interface RepoExecutionResult {
  repoPath?: string;
  branchName?: string;
  testSummary: string;
  changedFiles: string[];
  commitSha?: string;
  pushSucceeded: boolean;
  prUrl?: string;
  openclawText?: string;
}
