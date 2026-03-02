"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AsyncRotatingAuditLogger = void 0;
exports.hashArgs = hashArgs;
const node_crypto_1 = __importDefault(require("node:crypto"));
const promises_1 = __importDefault(require("node:fs/promises"));
const node_path_1 = __importDefault(require("node:path"));
class AsyncRotatingAuditLogger {
    logPath;
    rotatedPath;
    maxBytes;
    maxQueueEntries;
    hooks;
    queue = [];
    flushScheduled = false;
    flushing = false;
    droppedRecords = 0;
    writeErrors = 0;
    rotations = 0;
    constructor(logPath, maxBytes = 10 * 1024 * 1024, maxQueueEntries = 10_000, hooks = {}) {
        this.logPath = logPath;
        this.rotatedPath = `${logPath}.1`;
        this.maxBytes = maxBytes;
        this.maxQueueEntries = maxQueueEntries;
        this.hooks = hooks;
    }
    append(record) {
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
    async flushLoop() {
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
        }
        catch {
            // Fail-open: audit logging must never block execution.
            this.writeErrors += 1;
            this.hooks.onError?.();
        }
        finally {
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
    async appendWithRotation(payload) {
        await promises_1.default.mkdir(node_path_1.default.dirname(this.logPath), { recursive: true });
        let currentSize = 0;
        try {
            const stat = await promises_1.default.stat(this.logPath);
            currentSize = stat.size;
        }
        catch {
            currentSize = 0;
        }
        const incomingBytes = Buffer.byteLength(payload, "utf8");
        if (currentSize + incomingBytes > this.maxBytes) {
            await this.rotate();
        }
        await promises_1.default.appendFile(this.logPath, payload, "utf8");
    }
    async rotate() {
        await promises_1.default.rm(this.rotatedPath, { force: true });
        try {
            await promises_1.default.rename(this.logPath, this.rotatedPath);
            this.rotations += 1;
            this.hooks.onRotate?.();
        }
        catch {
            // If file does not exist yet, nothing to rotate.
        }
    }
    getStats() {
        return {
            queueDepth: this.queue.length,
            droppedRecords: this.droppedRecords,
            writeErrors: this.writeErrors,
            rotations: this.rotations,
        };
    }
}
exports.AsyncRotatingAuditLogger = AsyncRotatingAuditLogger;
function hashArgs(args) {
    const serialized = JSON.stringify(args, Object.keys(args).sort());
    return node_crypto_1.default.createHash("sha256").update(serialized, "utf8").digest("hex");
}
