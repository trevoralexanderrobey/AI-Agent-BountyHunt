const test = require("node:test");
const assert = require("node:assert/strict");

const { createExecutionQuotaStore } = require("../../security/execution-quota-store.js");

class MockRedisClient {
  constructor() {
    this.connected = false;
    this.nowMs = 1_700_000_000_000;
    this.zsets = new Map();
  }

  on() {}

  async connect() {
    this.connected = true;
  }

  async quit() {
    this.connected = false;
  }

  getSet(key) {
    if (!this.zsets.has(key)) {
      this.zsets.set(key, []);
    }
    return this.zsets.get(key);
  }

  evict(set, minScore) {
    for (let i = set.length - 1; i >= 0; i -= 1) {
      if (set[i].score <= minScore) {
        set.splice(i, 1);
      }
    }
  }

  async eval(_lua, payload) {
    const { keys, arguments: args } = payload;
    const [hourKey, minuteKey] = keys;
    const [member, hourWindowRaw, hourLimitRaw, minuteWindowRaw, minuteLimitRaw] = args;

    const hourWindowMs = Number(hourWindowRaw);
    const hourLimit = Number(hourLimitRaw);
    const minuteWindowMs = Number(minuteWindowRaw);
    const minuteLimit = Number(minuteLimitRaw);

    const hourSet = this.getSet(hourKey);
    const minuteSet = this.getSet(minuteKey);

    this.evict(hourSet, this.nowMs - hourWindowMs);
    this.evict(minuteSet, this.nowMs - minuteWindowMs);

    if (minuteLimit > 0 && minuteSet.length >= minuteLimit) {
      return [0, "EXECUTION_RATE_LIMIT_EXCEEDED", String(this.nowMs), String(minuteSet.length), String(hourSet.length)];
    }

    if (hourLimit > 0 && hourSet.length >= hourLimit) {
      return [0, "EXECUTION_QUOTA_EXCEEDED", String(this.nowMs), String(minuteSet.length), String(hourSet.length)];
    }

    if (!hourSet.some((entry) => entry.member === member)) {
      hourSet.push({ member, score: this.nowMs });
    }
    if (!minuteSet.some((entry) => entry.member === member)) {
      minuteSet.push({ member, score: this.nowMs });
    }

    return [1, "OK", String(this.nowMs), String(minuteSet.length), String(hourSet.length)];
  }
}

test("execution quota store enforces rolling minute burst and hourly limits", async () => {
  const redis = new MockRedisClient();
  const store = createExecutionQuotaStore({
    production: true,
    security: {
      executionQuotaPerHour: 3,
      executionBurstLimitPerMinute: 2,
      quotaRedisUrl: "redis://127.0.0.1:6379",
      quotaRedisPrefix: "openclaw:test",
    },
    client: redis,
  });

  const first = await store.consume({ principalId: "user-a", requestId: "req-1", toolSlug: "nmap" });
  const second = await store.consume({ principalId: "user-a", requestId: "req-2", toolSlug: "nmap" });
  const burstRejected = await store.consume({ principalId: "user-a", requestId: "req-3", toolSlug: "nmap" });

  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(burstRejected.ok, false);
  assert.equal(burstRejected.code, "EXECUTION_RATE_LIMIT_EXCEEDED");

  redis.nowMs += 61_000;

  const third = await store.consume({ principalId: "user-a", requestId: "req-4", toolSlug: "nmap" });
  const hourlyRejected = await store.consume({ principalId: "user-a", requestId: "req-5", toolSlug: "nmap" });

  assert.equal(third.ok, true);
  assert.equal(hourlyRejected.ok, false);
  assert.equal(hourlyRejected.code, "EXECUTION_QUOTA_EXCEEDED");

  await store.close();
});

test("execution quota store fails closed in production when storage is unavailable", async () => {
  const store = createExecutionQuotaStore({
    production: true,
    security: {
      executionQuotaPerHour: 5,
      executionBurstLimitPerMinute: 2,
      quotaRedisUrl: "",
    },
  });

  const result = await store.consume({
    principalId: "user-a",
    requestId: "req-fail-closed",
    toolSlug: "nmap",
  });

  assert.equal(result.ok, false);
  assert.equal(result.code, "EXECUTION_QUOTA_EXCEEDED");
});
