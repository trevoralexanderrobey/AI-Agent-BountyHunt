const test = require("node:test");
const assert = require("node:assert/strict");
const { PassThrough } = require("node:stream");

const { createHttpHandlers } = require("../../http/handlers.js");
const { createMetrics } = require("../../observability/metrics.js");

function createRequest({ method = "POST", path = "/api/v1/execute", headers = {}, body = "" }) {
  const req = new PassThrough();
  req.method = method;
  req.url = path;
  req.headers = headers;
  process.nextTick(() => {
    if (body) {
      req.write(body);
    }
    req.end();
  });
  return req;
}

function createResponseCollector() {
  const headers = {};
  const response = {
    statusCode: 200,
    headersSent: false,
    setHeader(name, value) {
      headers[String(name).toLowerCase()] = value;
    },
    end(payload) {
      response.headersSent = true;
      response.body = typeof payload === "string" ? payload : "";
    },
  };
  response.headers = headers;
  response.body = "";
  return response;
}

test("http handler rejects execution when principal identity is missing", async () => {
  const handlers = createHttpHandlers({
    supervisor: {
      execute: async () => ({ ok: true }),
      getStatus: async () => ({ ok: true, skills: [] }),
      getMetrics: () => ({ counters: [], histograms: [], gauges: [] }),
    },
    metrics: createMetrics(),
    authEnabled: false,
  });

  const req = createRequest({
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      slug: "nmap",
      method: "run",
      params: {},
    }),
  });
  const res = createResponseCollector();

  await handlers.handle(req, res);

  assert.equal(res.statusCode, 401);
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.error.code, "UNAUTHENTICATED_EXECUTION");
});

test("http handler maps execution burst quota rejection to 429", async () => {
  const handlers = createHttpHandlers({
    supervisor: {
      execute: async () => {
        const error = new Error("rate limit");
        error.code = "EXECUTION_RATE_LIMIT_EXCEEDED";
        throw error;
      },
      getStatus: async () => ({ ok: true, skills: [] }),
      getMetrics: () => ({ counters: [], histograms: [], gauges: [] }),
    },
    metrics: createMetrics(),
    authEnabled: false,
  });

  const req = createRequest({
    headers: {
      "content-type": "application/json",
      "x-principal-id": "user-a",
    },
    body: JSON.stringify({
      slug: "nmap",
      method: "run",
      params: {},
    }),
  });
  const res = createResponseCollector();

  await handlers.handle(req, res);

  assert.equal(res.statusCode, 429);
  const parsed = JSON.parse(res.body);
  assert.equal(parsed.error.code, "EXECUTION_RATE_LIMIT_EXCEEDED");
});
