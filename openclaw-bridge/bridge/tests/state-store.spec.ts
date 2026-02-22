import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { StateStore } from "../state-store";

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-bridge-state-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
});

describe("state store", () => {
  it("creates and persists jobs", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    const created = await store.createJob({
      instruction: "Fix bug",
      requester: "cli",
      repo_url: "https://github.com/openclaw/openclaw",
    });

    expect(created.id).toContain("job-");
    expect(created.status).toBe("queued");
    expect(store.listJobs()).toHaveLength(1);

    const loadedStore = new StateStore(root);
    await loadedStore.init();
    expect(loadedStore.listJobs()[0].id).toBe(created.id);
  });

  it("tracks status transitions", async () => {
    const root = await createTempDir();
    const store = new StateStore(root);
    await store.init();

    const created = await store.createJob({ instruction: "Test", requester: "codex" });

    const running = await store.updateStatus(created.id, "running");
    expect(running.status).toBe("running");
    expect(running.started_at).toBeTruthy();

    const failed = await store.updateStatus(created.id, "failed", {
      error_message: "boom",
    });
    expect(failed.status).toBe("failed");
    expect(failed.finished_at).toBeTruthy();
    expect(failed.error_message).toBe("boom");
  });
});
