const test = require("node:test");
const assert = require("node:assert/strict");

const { createResourceArbiter } = require("../../execution/resource-arbiter.js");

function limits(overrides = {}) {
  return {
    cpuShares: 128,
    memoryLimitMb: 256,
    maxRuntimeSeconds: 30,
    maxOutputBytes: 1024,
    ...overrides,
  };
}

test("resource arbiter creates deterministic lease ids and idempotent release", () => {
  const arbiter = createResourceArbiter({
    execution: {
      maxConcurrentContainersPerNode: 4,
      toolConcurrencyLimits: {
        nmap: 2,
      },
      nodeMemoryHardCapMb: 2048,
      nodeCpuHardCapShares: 2048,
    },
  });

  const first = arbiter.tryAcquire({
    requestId: "req-1",
    principalId: "user-a",
    toolSlug: "nmap",
    resourceLimits: limits(),
  });
  const second = arbiter.tryAcquire({
    requestId: "req-1",
    principalId: "user-a",
    toolSlug: "nmap",
    resourceLimits: limits(),
  });

  assert.equal(first.leaseId, second.leaseId);
  assert.equal(second.idempotent, true);

  const released = arbiter.release(first.leaseId);
  const releasedAgain = arbiter.release(first.leaseId);
  assert.equal(released.released, true);
  assert.equal(releasedAgain.released, false);
});

test("resource arbiter enforces node and tool caps", () => {
  const arbiter = createResourceArbiter({
    execution: {
      maxConcurrentContainersPerNode: 1,
      toolConcurrencyLimits: {
        nmap: 1,
      },
      nodeMemoryHardCapMb: 2048,
      nodeCpuHardCapShares: 2048,
    },
  });

  arbiter.tryAcquire({
    requestId: "req-cap-1",
    principalId: "user-a",
    toolSlug: "nmap",
    resourceLimits: limits(),
  });

  assert.throws(
    () =>
      arbiter.tryAcquire({
        requestId: "req-cap-2",
        principalId: "user-b",
        toolSlug: "nmap",
        resourceLimits: limits(),
      }),
    (error) => {
      assert.equal(error.code, "NODE_CAPACITY_EXCEEDED");
      return true;
    },
  );
});

test("resource arbiter enforces memory and CPU pressure limits", () => {
  const arbiter = createResourceArbiter({
    execution: {
      maxConcurrentContainersPerNode: 10,
      toolConcurrencyLimits: {
        nmap: 10,
      },
      nodeMemoryHardCapMb: 300,
      nodeCpuHardCapShares: 200,
    },
  });

  arbiter.tryAcquire({
    requestId: "req-pressure-1",
    principalId: "user-a",
    toolSlug: "nmap",
    resourceLimits: limits({ memoryLimitMb: 200, cpuShares: 100 }),
  });

  assert.throws(
    () =>
      arbiter.tryAcquire({
        requestId: "req-pressure-2",
        principalId: "user-b",
        toolSlug: "nmap",
        resourceLimits: limits({ memoryLimitMb: 200, cpuShares: 100 }),
      }),
    (error) => {
      assert.equal(error.code, "NODE_MEMORY_PRESSURE_EXCEEDED");
      return true;
    },
  );

  const cpuArbiter = createResourceArbiter({
    execution: {
      maxConcurrentContainersPerNode: 10,
      toolConcurrencyLimits: {
        nmap: 10,
      },
      nodeMemoryHardCapMb: 4096,
      nodeCpuHardCapShares: 150,
    },
  });

  cpuArbiter.tryAcquire({
    requestId: "req-cpu-1",
    principalId: "user-a",
    toolSlug: "nmap",
    resourceLimits: limits({ cpuShares: 100 }),
  });

  assert.throws(
    () =>
      cpuArbiter.tryAcquire({
        requestId: "req-cpu-2",
        principalId: "user-b",
        toolSlug: "nmap",
        resourceLimits: limits({ cpuShares: 100 }),
      }),
    (error) => {
      assert.equal(error.code, "NODE_CPU_SATURATION_EXCEEDED");
      return true;
    },
  );
});

test("resource arbiter reconstructs from active execution records", async () => {
  const arbiter = createResourceArbiter({
    execution: {
      maxConcurrentContainersPerNode: 10,
      toolConcurrencyLimits: {
        nmap: 10,
      },
      nodeMemoryHardCapMb: 4096,
      nodeCpuHardCapShares: 4096,
    },
  });

  const rebuild = await arbiter.reconstructFromActiveExecutions([
    {
      requestId: "req-rebuild-1",
      principalId: "user-a",
      principalHash: "aaaaaaaaaaaaaaaa",
      toolSlug: "nmap",
      resourceLimits: limits(),
      createdAt: Date.now(),
      containerId: "container-1",
    },
  ]);

  assert.equal(rebuild.ok, true);
  assert.equal(rebuild.restoredCount, 1);

  const snapshot = arbiter.getSnapshot();
  assert.equal(snapshot.totalLeases, 1);
  assert.equal(snapshot.leases[0].recovered, true);
});
