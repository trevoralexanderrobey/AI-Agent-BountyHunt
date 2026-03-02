const http = require("node:http");
const https = require("node:https");

const { STATUS_UP, STATUS_DOWN } = require("./peer-registry.js");

function normalizePositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function createPeerHeartbeat(options = {}) {
  const peerRegistry = options.peerRegistry;
  if (!peerRegistry || typeof peerRegistry.listPeers !== "function" || typeof peerRegistry.updatePeerHealth !== "function") {
    throw new Error("peerRegistry with listPeers() and updatePeerHealth() is required");
  }

  const intervalMs = normalizePositiveInt(options.intervalMs, 60000);
  const timeoutMs = normalizePositiveInt(options.timeoutMs, 5000);

  let timer = null;
  let running = false;

  function probePeer(peer) {
    return new Promise((resolve) => {
      const startedAt = Date.now();
      let endpoint;

      try {
        endpoint = new URL("/health", peer.url);
      } catch {
        resolve({
          status: STATUS_DOWN,
          latencyMs: 0,
          timestamp: Date.now(),
        });
        return;
      }

      const transport = endpoint.protocol === "https:" ? https : http;
      const req = transport.request(
        {
          protocol: endpoint.protocol,
          hostname: endpoint.hostname,
          port: endpoint.port || (endpoint.protocol === "https:" ? 443 : 80),
          path: `${endpoint.pathname}${endpoint.search}`,
          method: "GET",
          headers: {
            accept: "application/json",
          },
        },
        (res) => {
          let raw = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => {
            raw += chunk;
          });
          res.on("end", () => {
            const latencyMs = Date.now() - startedAt;
            let up = res.statusCode >= 200 && res.statusCode < 300;
            let metadata = {};

            if (up && raw) {
              try {
                const parsed = JSON.parse(raw);
                if (parsed && typeof parsed.status === "string" && parsed.status.toLowerCase() === "unhealthy") {
                  up = false;
                }
                if (parsed && typeof parsed === "object") {
                  metadata = {
                    executionPolicyHash:
                      typeof parsed.execution_policy_hash === "string" ? parsed.execution_policy_hash : undefined,
                    secretManifestHash:
                      typeof parsed.secret_manifest_hash === "string" ? parsed.secret_manifest_hash : undefined,
                    workloadManifestHash:
                      typeof parsed.workload_manifest_hash === "string" ? parsed.workload_manifest_hash : undefined,
                    executionPolicyVersion:
                      Number.isInteger(Number(parsed.execution_policy_version))
                        ? Number(parsed.execution_policy_version)
                        : undefined,
                    executionConfigHash:
                      typeof parsed.execution_config_hash === "string" ? parsed.execution_config_hash : undefined,
                    executionConfigVersion:
                      typeof parsed.execution_config_version === "string" ? parsed.execution_config_version : undefined,
                    expectedExecutionConfigVersion:
                      typeof parsed.expected_execution_config_version === "string"
                        ? parsed.expected_execution_config_version
                        : undefined,
                    nodeId: typeof parsed.node_id === "string" ? parsed.node_id : undefined,
                  };
                }
              } catch {
                // Non-JSON success from /health still counts as UP.
              }
            }

            resolve({
              status: up ? STATUS_UP : STATUS_DOWN,
              latencyMs,
              timestamp: Date.now(),
              metadata,
            });
          });
        },
      );

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error("heartbeat timeout"));
      });

      req.on("error", () => {
        resolve({
          status: STATUS_DOWN,
          latencyMs: Date.now() - startedAt,
          timestamp: Date.now(),
        });
      });

      req.end();
    });
  }

  async function runOnce() {
    const peers = peerRegistry.listPeers();
    await Promise.all(
      peers.map(async (peer) => {
        const result = await probePeer(peer);
        peerRegistry.updatePeerHealth(peer.peerId, {
          status: result.status,
          lastLatencyMs: result.latencyMs,
          lastHeartbeat: result.timestamp,
          executionConfigHash:
            result && result.metadata && typeof result.metadata.executionConfigHash === "string"
              ? result.metadata.executionConfigHash
              : undefined,
          executionPolicyHash:
            result && result.metadata && typeof result.metadata.executionPolicyHash === "string"
              ? result.metadata.executionPolicyHash
              : undefined,
          secretManifestHash:
            result && result.metadata && typeof result.metadata.secretManifestHash === "string"
              ? result.metadata.secretManifestHash
              : undefined,
          workloadManifestHash:
            result && result.metadata && typeof result.metadata.workloadManifestHash === "string"
              ? result.metadata.workloadManifestHash
              : undefined,
          executionConfigVersion:
            result && result.metadata && typeof result.metadata.executionConfigVersion === "string"
              ? result.metadata.executionConfigVersion
              : undefined,
          executionPolicyVersion:
            result &&
            result.metadata &&
            Number.isInteger(Number(result.metadata.executionPolicyVersion))
              ? Number(result.metadata.executionPolicyVersion)
              : undefined,
          expectedExecutionConfigVersion:
            result && result.metadata && typeof result.metadata.expectedExecutionConfigVersion === "string"
              ? result.metadata.expectedExecutionConfigVersion
              : undefined,
          nodeId: result && result.metadata && typeof result.metadata.nodeId === "string" ? result.metadata.nodeId : undefined,
        });
      }),
    );
  }

  function start() {
    if (running) {
      return;
    }
    running = true;

    timer = setInterval(() => {
      runOnce().catch(() => {
        // Heartbeat failures should not crash supervisor process.
      });
    }, intervalMs);

    if (timer && typeof timer.unref === "function") {
      timer.unref();
    }

    runOnce().catch(() => {
      // Initial heartbeat failures should not crash startup.
    });
  }

  function stop() {
    running = false;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function isRunning() {
    return running;
  }

  return {
    start,
    stop,
    runOnce,
    isRunning,
    intervalMs,
    timeoutMs,
  };
}

module.exports = {
  createPeerHeartbeat,
};
