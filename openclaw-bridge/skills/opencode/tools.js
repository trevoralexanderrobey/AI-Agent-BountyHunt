/* eslint-disable no-console */

const DEFAULT_DAEMON_BASE_URL = "http://127.0.0.1:8091";

function normalizeBaseUrl(url) {
  return String(url || "").trim().replace(/\/+$/, "");
}

function getDaemonBaseUrl() {
  return normalizeBaseUrl(process.env.OPENCODE_DAEMON_BASE_URL || DEFAULT_DAEMON_BASE_URL);
}

async function postJson(url, payload, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload || {}),
      signal: controller.signal,
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const error = new Error(data && data.error ? data.error : `HTTP ${response.status}`);
      error.statusCode = response.status;
      throw error;
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(url, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      signal: controller.signal,
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const error = new Error(data && data.error ? data.error : `HTTP ${response.status}`);
      error.statusCode = response.status;
      throw error;
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

async function opencode_session_create(args = {}) {
  const url = `${getDaemonBaseUrl()}/session`;
  const payload = {
    session_id: args.session_id,
    title: args.title,
    metadata: args.metadata,
  };
  return postJson(url, payload);
}

async function opencode_session_message(args = {}) {
  const sessionId = String(args.session_id || "").trim();
  if (!sessionId) {
    throw new Error("session_id is required");
  }

  const message = String(args.message || args.prompt || "").trim();
  if (!message) {
    throw new Error("message is required");
  }

  const route = `/session/${encodeURIComponent(sessionId)}/message`;
  const payload = {
    message,
    model: args.model,
    agent: args.agent,
    system: args.system,
    parts: args.parts,
    no_reply: args.no_reply ?? args.noReply,
  };

  return postJson(`${getDaemonBaseUrl()}${route}`, payload);
}

async function opencode_session_state(args = {}) {
  const sessionId = String(args.session_id || "").trim();
  if (!sessionId) {
    throw new Error("session_id is required");
  }

  const route = `/session/${encodeURIComponent(sessionId)}/state`;
  return getJson(`${getDaemonBaseUrl()}${route}`);
}

async function opencode_session_close(args = {}) {
  const sessionId = String(args.session_id || "").trim();
  if (!sessionId) {
    throw new Error("session_id is required");
  }

  const route = `/session/${encodeURIComponent(sessionId)}/close`;
  return postJson(`${getDaemonBaseUrl()}${route}`, {});
}

module.exports = {
  opencode_session_create,
  opencode_session_message,
  opencode_session_state,
  opencode_session_close,
};
