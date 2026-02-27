const fs = require("node:fs");

const ADAPTER_CONSTRUCTORS = Object.freeze({
  curl: () => require("../tools/adapters/curl-adapter.js").CurlAdapter,
  nslookup: () => require("../tools/adapters/nslookup-adapter.js").NslookupAdapter,
  whois: () => require("../tools/adapters/whois-adapter.js").WhoisAdapter,
  hashcat: () => require("../tools/adapters/hashcat-adapter.js").HashcatAdapter,
  sqlmap: () => require("../tools/adapters/sqlmap-adapter.js").SqlmapAdapter,
  nikto: () => require("../tools/adapters/nikto-adapter.js").NiktoAdapter,
  aircrack: () => require("../tools/adapters/aircrack-adapter.js").AircrackAdapter,
  msfvenom: () => require("../tools/adapters/msfvenom-adapter.js").MsfvenomAdapter,
  ffuf: () => require("../tools/adapters/ffuf-adapter.js").FfufAdapter,
});

function normalizeSlug(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function makeError(code, message, details = {}) {
  return {
    ok: false,
    error: {
      code: String(code || "TOOL_EXECUTION_ERROR"),
      message: String(message || "Container tool runner failed"),
      details,
    },
  };
}

function readRequestPayload() {
  const requestPath =
    typeof process.env.OPENCLAW_REQUEST_PATH === "string" && process.env.OPENCLAW_REQUEST_PATH.trim()
      ? process.env.OPENCLAW_REQUEST_PATH.trim()
      : "/scratch/request.json";

  const raw = fs.readFileSync(requestPath, "utf8");
  const payload = JSON.parse(raw);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("request payload must be an object");
  }
  return payload;
}

function resolveAdapter(slug) {
  const getter = ADAPTER_CONSTRUCTORS[slug];
  if (!getter || typeof getter !== "function") {
    throw new Error(`Unsupported container tool slug '${slug}'`);
  }
  const AdapterCtor = getter();
  if (typeof AdapterCtor !== "function") {
    throw new Error(`Adapter constructor missing for slug '${slug}'`);
  }
  return new AdapterCtor();
}

async function run() {
  let payload;
  try {
    payload = readRequestPayload();
  } catch (error) {
    return makeError("INVALID_CONTAINER_REQUEST", "Unable to read container request payload", {
      reason: error && error.message ? error.message : String(error),
    });
  }

  const slug = normalizeSlug(payload.slug);
  if (!slug) {
    return makeError("INVALID_CONTAINER_REQUEST", "Container request payload requires slug");
  }

  const params = payload.params && typeof payload.params === "object" && !Array.isArray(payload.params) ? payload.params : {};
  const timeout = Number.isFinite(Number(payload.timeout)) ? Number(payload.timeout) : 30000;
  const requestId = typeof payload.requestId === "string" ? payload.requestId : "container-runner";

  let adapter;
  try {
    adapter = resolveAdapter(slug);
  } catch (error) {
    return makeError("INVALID_TOOL_REQUEST", "Unable to load tool adapter in container", {
      slug,
      reason: error && error.message ? error.message : String(error),
    });
  }

  try {
    const rawResult = await adapter.executeImpl({
      params,
      timeout,
      requestId,
    });

    return {
      ok: true,
      rawResult,
    };
  } catch (error) {
    const code = error && typeof error.code === "string" ? error.code : "TOOL_EXECUTION_ERROR";
    const message = error && typeof error.message === "string" ? error.message : "Container tool execution failed";
    return makeError(code, message, {
      slug,
    });
  }
}

run()
  .then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result && result.ok === true) {
      process.exit(0);
      return;
    }
    process.exit(1);
  })
  .catch((error) => {
    const payload = makeError(
      "CONTAINER_TOOL_RUNNER_ERROR",
      error && error.message ? error.message : String(error),
      {},
    );
    process.stdout.write(`${JSON.stringify(payload)}\n`);
    process.exit(1);
  });
