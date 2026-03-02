import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export interface SupervisorAuditRecord {
  requestId: string;
  tool: string;
  caller: string;
  timestamp: string;
  argsHash: string;
  resultStatus: "ok" | "error";
  role?: string;
  source?: string;
  code?: string;
  details?: Record<string, unknown>;
}

export interface AuditLoggerStats {
  queueDepth: number;
  droppedRecords: number;
  writeErrors: number;
  rotations: number;
}

export interface AuditLoggerHooks {
  onDrop?: (count: number) => void;
  onError?: () => void;
  onRotate?: () => void;
}

export class AsyncRotatingAuditLogger {
  private readonly logPath: string;
  private readonly rotatedPath: string;
  private readonly maxBytes: number;
  private readonly maxQueueEntries: number;
  private readonly hooks: AuditLoggerHooks;
  private queue: string[] = [];
  private flushScheduled = false;
  private flushing = false;
  private droppedRecords = 0;
  private writeErrors = 0;
  private rotations = 0;

  constructor(logPath: string, maxBytes = 10 * 1024 * 1024, maxQueueEntries = 10_000, hooks: AuditLoggerHooks = {}) {
    this.logPath = logPath;
    this.rotatedPath = `${logPath}.1`;
    this.maxBytes = maxBytes;
    this.maxQueueEntries = maxQueueEntries;
    this.hooks = hooks;
  }

  append(record: SupervisorAuditRecord): boolean {
    if (this.queue.length >= this.maxQueueEntries) {
      this.droppedRecords += 1;
      this.hooks.onDrop?.(1);
      return false;
    }
    const line = `${JSON.stringify(record)}\n`;
    this.queue.push(line);
    if (!this.flushScheduled) {
      this.flushScheduled = true;
      setImmediate(() => {
        void this.flushLoop();
      });
    }
    return true;
  }

  private async flushLoop(): Promise<void> {
    if (this.flushing) {
      return;
    }
    this.flushing = true;
    try {
      while (this.queue.length > 0) {
        const batch = this.queue.splice(0, 100);
        const payload = batch.join("");
        await this.appendWithRotation(payload);
      }
    } catch {
      // Fail-open: audit logging must never block execution.
      this.writeErrors += 1;
      this.hooks.onError?.();
    } finally {
      this.flushing = false;
      this.flushScheduled = false;
      if (this.queue.length > 0) {
        this.flushScheduled = true;
        setImmediate(() => {
          void this.flushLoop();
        });
      }
    }
  }

  private async appendWithRotation(payload: string): Promise<void> {
    await fs.mkdir(path.dirname(this.logPath), { recursive: true });

    let currentSize = 0;
    try {
      const stat = await fs.stat(this.logPath);
      currentSize = stat.size;
    } catch {
      currentSize = 0;
    }

    const incomingBytes = Buffer.byteLength(payload, "utf8");
    if (currentSize + incomingBytes > this.maxBytes) {
      await this.rotate();
    }

    await fs.appendFile(this.logPath, payload, "utf8");
  }

  private async rotate(): Promise<void> {
    await fs.rm(this.rotatedPath, { force: true });
    try {
      await fs.rename(this.logPath, this.rotatedPath);
      this.rotations += 1;
      this.hooks.onRotate?.();
    } catch {
      // If file does not exist yet, nothing to rotate.
    }
  }

  getStats(): AuditLoggerStats {
    return {
      queueDepth: this.queue.length,
      droppedRecords: this.droppedRecords,
      writeErrors: this.writeErrors,
      rotations: this.rotations,
    };
  }
}

export function hashArgs(args: Record<string, unknown>): string {
  const serialized = JSON.stringify(args, Object.keys(args).sort());
  return crypto.createHash("sha256").update(serialized, "utf8").digest("hex");
}
