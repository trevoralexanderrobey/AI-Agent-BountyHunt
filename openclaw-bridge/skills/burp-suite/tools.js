/* eslint-disable no-console */

const http = require("node:http");
const https = require("node:https");

const DEFAULT_BRIDGE_BASE_URL = "http://127.0.0.1:8787";

function getBridgeBaseUrl() {
  const raw =
    (process.env.OPENCLAW_BRIDGE_BASE_URL || "").trim() ||
    (process.env.BRIDGE_BASE_URL || "").trim() ||
    DEFAULT_BRIDGE_BASE_URL;
  return raw.replace(/\/+$/, "");
}

function isTransportError(err) {
  const msg = String(err && err.message ? err.message : err || "").toLowerCase();
  return (
    msg.includes("econnrefused") ||
    msg.includes("socket hang up") ||
    msg.includes("self signed") ||
    msg.includes("unable to verify") ||
    msg.includes("eproto") ||
    msg.includes("wrong version number") ||
    msg.includes("expected http/") ||
    msg.includes("network") ||
    msg.includes("fetch failed")
  );
}

function postJson(urlString, payload, timeoutMs) {
  const url = new URL(urlString);
  const isHttps = url.protocol === "https:";
  const mod = isHttps ? https : http;
  const data = JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (res) => {
        let text = "";
        res.on("data", (chunk) => {
          text += String(chunk);
        });
        res.on("end", () => {
          let json;
          try {
            json = JSON.parse(text || "{}");
          } catch {
            reject(new Error(`Bridge returned non-JSON (${res.statusCode}): ${text.slice(0, 500)}`));
            return;
          }
          resolve({ statusCode: res.statusCode || 0, json });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`Bridge timeout after ${timeoutMs}ms`));
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function makeBridgeStatusError(message, statusCode) {
  const err = new Error(message);
  err.bridgeHttpStatus = statusCode;
  return err;
}

function isBridgeStatusError(err) {
  return Boolean(err && typeof err === "object" && Number.isFinite(Number(err.bridgeHttpStatus)));
}

async function callBridge(tool, args) {
  const baseUrl = getBridgeBaseUrl();
  const timeoutMs = Number.parseInt(process.env.OPENCLAW_BRIDGE_TIMEOUT_MS || "15000", 10);

  const baseCandidates = [baseUrl];
  if (baseUrl.startsWith("http://")) {
    baseCandidates.push(baseUrl.replace(/^http:\/\//, "https://"));
  } else if (baseUrl.startsWith("https://")) {
    baseCandidates.push(baseUrl.replace(/^https:\/\//, "http://"));
  }

  let lastError = null;
  try {
    for (const candidate of baseCandidates) {
      const url = `${candidate}/execute-tool`;
      try {
        const { statusCode, json } = await postJson(url, { tool, args }, timeoutMs);
        if (statusCode < 200 || statusCode >= 300) {
          throw makeBridgeStatusError(json && json.error ? json.error : `Bridge error ${statusCode}`, statusCode);
        }
        return json;
      } catch (error) {
        lastError = error;
        if (isBridgeStatusError(error) || !isTransportError(error)) {
          throw error;
        }
      }
    }
    throw lastError || new Error("Unknown bridge transport error");
  } catch (error) {
    throw new Error(`Bridge call failed for ${tool}: ${error.message || String(error)}`);
  }
}

async function burp_get_history(args) {
  const response = await callBridge("burp_get_history", args || {});
  return response.result ?? response;
}

async function burp_analyze_request(args) {
  const response = await callBridge("burp_analyze_request", args || {});
  return response.result ?? response;
}

async function burp_active_scan(args) {
  const response = await callBridge("burp_active_scan", args || {});
  return response.result ?? response;
}

async function burp_get_raw_request(args) {
  const response = await callBridge("burp_get_raw_request", args || {});
  return response.result ?? response;
}

function getItemsFromHistoryPayload(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.items)) return payload.items;
  if (Array.isArray(payload.history)) return payload.history;
  if (payload.result) return getItemsFromHistoryPayload(payload.result);
  return [];
}

function readString(value) {
  return typeof value === "string" ? value : "";
}

function itemIdentity(item) {
  const id =
    item?.id ??
    item?.message_id ??
    item?.requestId ??
    item?.request_id ??
    null;

  const method = readString(item?.method || item?.request_method || item?.verb).toUpperCase();
  const url = readString(item?.url || item?.request_url || item?.uri);
  const statusRaw = item?.status ?? item?.status_code ?? item?.response_status ?? null;
  const status = Number.isFinite(Number(statusRaw)) ? Number(statusRaw) : null;

  return {
    id,
    method: method || "UNKNOWN",
    url: url || "(unknown)",
    status,
  };
}

function collectHeuristics(item) {
  const blob = JSON.stringify(item || {}).toLowerCase();
  const reasons = [];
  let score = 0;

  const rules = [
    {
      score: 3,
      reason: "Server-initiated processing surface (webhook/callback/queue/event endpoint)",
      patterns: [
        "webhook",
        "callback",
        "queue",
        "event",
        "consumer",
        "worker",
        "ingest",
        "notify",
        "notification",
        "sync",
      ],
    },
    {
      score: 3,
      reason: "Potential parser/deserialization surface (binary/protobuf/serialized payload indicators)",
      patterns: [
        "application/octet-stream",
        "application/x-java-serialized-object",
        "protobuf",
        "grpc",
        "bplist",
        "multipart/form-data",
      ],
    },
    {
      score: 2,
      reason: "Potential URL-fetch/SSRF-style backend processing keywords",
      patterns: [
        "fetch",
        "proxy",
        "import",
        "url=",
        "redirect_uri",
        "callback_url",
        "webhook_url",
      ],
    },
    {
      score: 2,
      reason: "Cloud/internal metadata hints in observed traffic",
      patterns: ["169.254.169.254", "imds", "metadata", "kubernetes", "/latest/meta-data"],
    },
    {
      score: 1,
      reason: "Potential backend error signal (5xx / exception-like traces)",
      patterns: [" 500", " 502", " 503", " 504", "exception", "stacktrace", "traceback"],
    },
  ];

  for (const rule of rules) {
    if (rule.patterns.some((pattern) => blob.includes(pattern))) {
      score += rule.score;
      reasons.push(rule.reason);
    }
  }

  return { score, reasons };
}

async function burp_zero_click_triage(args = {}) {
  const limit = Number.parseInt(String(args.limit ?? 75), 10);
  const maxCandidates = Number.parseInt(String(args.maxCandidates ?? 12), 10);
  const inScope = typeof args.inScope === "boolean" ? args.inScope : true;
  const fromId = Number.isFinite(Number(args.fromId)) ? Number(args.fromId) : undefined;

  let history;
  try {
    history = await burp_get_history({
      limit: Number.isFinite(limit) && limit > 0 ? limit : 75,
      inScope,
      ...(typeof fromId === "number" ? { fromId } : {}),
    });
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    return {
      mode: "defensive-zero-click-triage",
      unavailable: true,
      scanned_items: 0,
      in_scope_only: inScope,
      candidate_count: 0,
      candidates: [],
      error: message,
      safe_next_steps: [
        "Start Burp Suite and ensure the BionicLink extension is loaded and healthy.",
        "Verify bridge reachability at http://127.0.0.1:8787/health and BionicLink at http://127.0.0.1:8090/health.",
        "Re-run burp_zero_click_triage after Burp traffic is flowing in-scope.",
      ],
      notes: [
        "History acquisition failed before heuristic triage.",
        "For policy-safe planning/reporting, pair with the zero-click-rce-bounty-research skill.",
      ],
    };
  }

  const items = getItemsFromHistoryPayload(history);
  const candidates = [];

  for (const item of items) {
    const meta = itemIdentity(item);
    const triage = collectHeuristics(item);
    if (triage.score <= 0) continue;
    candidates.push({
      id: meta.id,
      method: meta.method,
      url: meta.url,
      status: meta.status,
      score: triage.score,
      reasons: triage.reasons,
    });
  }

  candidates.sort((a, b) => b.score - a.score);
  const capped = candidates.slice(0, Number.isFinite(maxCandidates) && maxCandidates > 0 ? maxCandidates : 12);

  return {
    mode: "defensive-zero-click-triage",
    scanned_items: items.length,
    in_scope_only: inScope,
    candidate_count: capped.length,
    candidates: capped,
    safe_next_steps: [
      "Use burp_analyze_request on top candidates to validate behavior with low-noise, non-destructive requests.",
      "Capture deterministic evidence only (status deltas, parser failures, correlation IDs, reproducibility).",
      "Avoid exploit payloads; focus on root-cause hypotheses, mitigations, and report-quality proof.",
    ],
    notes: [
      "Heuristic triage only; this tool prioritizes likely backend processing surfaces.",
      "For policy-safe planning/reporting, pair with the zero-click-rce-bounty-research skill.",
    ],
  };
}

module.exports = {
  burp_get_history,
  burp_analyze_request,
  burp_active_scan,
  burp_get_raw_request,
  burp_zero_click_triage,
};
