import { URL } from "node:url";
import type { BionicLinkHeader, BionicLinkHistoryItem, BionicLinkHistoryResponse, BionicLinkRepeaterResponse, BionicLinkScanResponse } from "./bioniclink-client";

const DROP_REQUEST_HEADERS = new Set([
  "accept",
  "accept-language",
  "accept-encoding",
  "cache-control",
  "connection",
  "dnt",
  "pragma",
  "priority",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "upgrade-insecure-requests",
  "user-agent",
]);

const DROP_RESPONSE_HEADERS = new Set([
  "alt-svc",
  "cache-control",
  "connection",
  "content-security-policy-report-only",
  "date",
  "etag",
  "expires",
  "last-modified",
  "pragma",
  "server-timing",
  "strict-transport-security",
  "vary",
  "via",
  "x-cache",
  "x-cache-hits",
  "x-served-by",
  "x-timer",
]);

export interface TspOptions {
  /**
   * When enabled, include raw headers/bodies from BionicLink.
   *
   * Safety: this will only take effect when BURP_ALLOW_RAW_DATA=true is set in the bridge environment.
   */
  unfiltered?: boolean;
}

function isBurpRawDataEnabled(): boolean {
  const value = (process.env.BURP_ALLOW_RAW_DATA || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

export interface TspHistoryItem {
  id: number;
  method: string;
  host: string;
  path: string;
  status: number;
  in_scope: boolean;
  resp_len: number;
  resp_type?: string;
  auth_header?: string;
  cookie_header?: string;
  set_cookie_headers?: string[];
  cookie_names?: string[];
  set_cookie_names?: string[];
  body_preview?: string;
  repeats?: number;

  // Raw fields (only present when opts.unfiltered=true AND BURP_ALLOW_RAW_DATA=true).
  url?: string;
  request_headers?: BionicLinkHeader[];
  request_body?: string;
  response_headers?: BionicLinkHeader[];
  response_body?: string;
}

export interface TspHistorySummary {
  ok: true;
  tool: "burp_get_history";
  meta: {
    source_count: number;
    returned_count: number;
    deduped_count: number;
    history_size?: number;
  };
  items: TspHistoryItem[];
}

export interface TspRepeaterSummary {
  ok: true;
  tool: "burp_analyze_request";
  url: string;
  method: string;
  in_scope: boolean;
  status: number;
  resp_len: number;
  resp_type?: string;
  location?: string;
  set_cookie_names?: string[];
  body_preview?: string;

  // Raw fields (only present when opts.unfiltered=true AND BURP_ALLOW_RAW_DATA=true).
  request_headers?: BionicLinkHeader[];
  request_body?: string;
  response_headers?: BionicLinkHeader[];
  response_body?: string;
}

export interface TspScanSummary {
  ok: true;
  tool: "burp_active_scan";
  url: string;
  method: string;
  in_scope: boolean;
  status_message: string;
  insertion_point_count: number;
}

function headerName(header: BionicLinkHeader): string {
  return (header.name || "").trim().toLowerCase();
}

function headerValue(header: BionicLinkHeader): string {
  return String(header.value || "").trim();
}

function getHeader(headers: BionicLinkHeader[], name: string): string | undefined {
  const target = name.toLowerCase();
  for (const h of headers) {
    if (headerName(h) === target) return headerValue(h);
  }
  return undefined;
}

function getHeaders(headers: BionicLinkHeader[], name: string): string[] {
  const target = name.toLowerCase();
  const values: string[] = [];
  for (const h of headers) {
    if (headerName(h) === target) values.push(headerValue(h));
  }
  return values;
}

function truncate(input: string, maxChars: number): string {
  const trimmed = (input || "").trim();
  if (trimmed.length <= maxChars) return trimmed;
  return `${trimmed.slice(0, maxChars)}...<truncated>`;
}

function cleanWhitespace(input: string): string {
  return (input || "").replace(/\s+/g, " ").trim();
}

function summarizeAuthHeader(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const parts = trimmed.split(/\s+/, 2);
  if (parts.length === 1) return parts[0].slice(0, 12) + (parts[0].length > 12 ? "..." : "");
  const scheme = parts[0];
  const token = parts[1];
  const head = token.slice(0, 12);
  return `${scheme} ${head}${token.length > head.length ? "..." : ""}`;
}

function cookieNamesFromHeader(raw: string | undefined): string[] | undefined {
  if (!raw) return undefined;
  const names = raw
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => part.split("=", 1)[0]?.trim())
    .filter((name): name is string => Boolean(name))
    .slice(0, 12);
  return names.length > 0 ? Array.from(new Set(names)) : undefined;
}

function cookieNamesFromSetCookie(headers: BionicLinkHeader[]): string[] | undefined {
  const setCookies = getHeaders(headers, "set-cookie");
  if (setCookies.length === 0) return undefined;
  const names = setCookies
    .map((value) => value.split("=", 1)[0]?.trim())
    .filter((name): name is string => Boolean(name))
    .slice(0, 12);
  return names.length > 0 ? Array.from(new Set(names)) : undefined;
}

function normalizePath(pathWithQuery: string): string {
  const [pathnameRaw, queryRaw] = pathWithQuery.split("?", 2);
  const pathname = pathnameRaw || "/";

  const segments = pathname
    .split("/")
    .map((seg) => seg.trim())
    .map((seg) => {
      if (!seg) return "";
      if (/^[0-9]+$/.test(seg)) return "{id}";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{uuid}";
      if (/^[0-9a-f]{16,}$/i.test(seg)) return "{hex}";
      return seg;
    });
  const normalizedPathname = segments.join("/");

  if (!queryRaw) return normalizedPathname;

  // Only keep query keys, not values (token + secret hygiene).
  const keys = queryRaw
    .split("&")
    .map((kv) => kv.split("=", 1)[0])
    .map((k) => k?.trim())
    .filter((k): k is string => Boolean(k))
    .slice(0, 10);

  if (keys.length === 0) return normalizedPathname;
  const suffix = queryRaw.split("&").length > keys.length ? "&..." : "";
  return `${normalizedPathname}?${keys.join("&")}${suffix}`;
}

function summarizeHtml(body: string): string {
  const text = body || "";
  const titleMatch = text.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
  const title = titleMatch ? cleanWhitespace(titleMatch[1]) : "";

  const inputNames = Array.from(
    new Set(
      Array.from(text.matchAll(/<input[^>]+name=[\"']([^\"']{1,60})[\"']/gi))
        .map((m) => m[1])
        .filter(Boolean),
    ),
  ).slice(0, 10);

  const links = Array.from(
    new Set(
      Array.from(text.matchAll(/<a[^>]+href=[\"']([^\"']{1,120})[\"']/gi))
        .map((m) => m[1])
        .filter(Boolean),
    ),
  ).slice(0, 8);

  const nextSignals: string[] = [];
  if (text.includes("/_next/") || text.includes("__NEXT_DATA__")) nextSignals.push("Next.js");

  const parts: string[] = [];
  if (title) parts.push(`HTML: '${title}'`);
  if (inputNames.length > 0) parts.push(`Inputs: [${inputNames.join(", ")}]`);
  if (links.length > 0) parts.push(`Links: [${links.join(", ")}]`);
  if (nextSignals.length > 0) parts.push(`Signals: ${nextSignals.join(", ")}`);

  if (parts.length > 0) return parts.join(". ");
  return truncate(cleanWhitespace(text), 400);
}

function summarizeJson(body: string): string {
  try {
    const parsed = JSON.parse(body) as unknown;
    if (Array.isArray(parsed)) {
      const n = parsed.length;
      const first = parsed[0];
      if (first && typeof first === "object" && !Array.isArray(first)) {
        const keys = Object.keys(first as Record<string, unknown>).slice(0, 12);
        return `JSON Array(len=${n}) item0.keys=[${keys.join(", ")}]`;
      }
      return `JSON Array(len=${n}) item0.type=${typeof first}`;
    }
    if (parsed && typeof parsed === "object") {
      const keys = Object.keys(parsed as Record<string, unknown>).slice(0, 20);
      return `JSON Object keys=[${keys.join(", ")}]`;
    }
  } catch {
    // ignore
  }
  return truncate(cleanWhitespace(body), 400);
}

function summarizeBody(respType: string | undefined, mimeType: string | undefined, body: string | undefined): string | undefined {
  const raw = (body || "").trim();
  if (!raw) return undefined;

  const type = (respType || "").toLowerCase();
  const mime = (mimeType || "").toLowerCase();

  if (type.includes("application/json") || mime.includes("json") || raw.startsWith("{") || raw.startsWith("[")) {
    return summarizeJson(raw);
  }

  if (type.includes("text/html") || mime.includes("html") || raw.includes("<html") || raw.includes("<title")) {
    return summarizeHtml(raw);
  }

  // Skip obvious binary-ish content that will explode tokens.
  if (mime.startsWith("image_") || mime === "sound" || mime === "video" || mime.startsWith("font_") || mime.includes("application")) {
    return "<omitted: binary>";
  }

  return truncate(cleanWhitespace(raw), 400);
}

export function summarizeTraffic(item: BionicLinkHistoryItem, opts?: TspOptions): TspHistoryItem {
  const rawEnabled = Boolean(opts?.unfiltered) && isBurpRawDataEnabled();
  const requestHeaders = item.request_headers || [];
  const responseHeaders = item.response_headers || [];

  const authRaw = getHeader(requestHeaders, "authorization");
  const cookieRaw = getHeader(requestHeaders, "cookie");
  const auth = rawEnabled ? authRaw : summarizeAuthHeader(authRaw);
  const cookieNames = cookieNamesFromHeader(cookieRaw);
  const setCookieNames = cookieNamesFromSetCookie(responseHeaders);
  const setCookieHeaders = getHeaders(responseHeaders, "set-cookie");
  const respType = getHeader(responseHeaders, "content-type");

  const base: TspHistoryItem = {
    id: item.id,
    method: item.method,
    host: item.host,
    // Full fidelity should not normalize/redact query values.
    path: rawEnabled ? item.path || "/" : normalizePath(item.path || "/"),
    status: item.status,
    in_scope: item.in_scope,
    resp_len: item.response_len,
    resp_type: respType ? respType.split(";")[0]?.trim() : undefined,
    auth_header: auth,
    cookie_header: rawEnabled ? cookieRaw : undefined,
    set_cookie_headers: rawEnabled && setCookieHeaders.length > 0 ? setCookieHeaders : undefined,
    cookie_names: cookieNames,
    set_cookie_names: setCookieNames,
    body_preview: rawEnabled ? undefined : summarizeBody(respType, item.mime_type, item.response_body),
  };

  if (!rawEnabled) return base;

  return {
    ...base,
    url: item.url,
    request_headers: requestHeaders,
    request_body: item.request_body,
    response_headers: responseHeaders,
    response_body: item.response_body,
  };
}

export function summarizeHistory(payload: BionicLinkHistoryResponse, opts?: TspOptions): TspHistorySummary {
  const sourceItems = Array.isArray(payload.items) ? payload.items : [];
  const dedupMap = new Map<string, { item: TspHistoryItem; count: number }>();

  for (const rawItem of sourceItems) {
    const tspItem = summarizeTraffic(rawItem, opts);
    const key = `${tspItem.method} ${tspItem.host}${tspItem.path}`;
    const existing = dedupMap.get(key);
    if (!existing) {
      dedupMap.set(key, { item: tspItem, count: 1 });
      continue;
    }
    existing.count += 1;
    // keep most recent by id
    if (tspItem.id >= existing.item.id) {
      existing.item = tspItem;
    }
  }

  const items = Array.from(dedupMap.values())
    .map((entry) => (entry.count > 1 ? { ...entry.item, repeats: entry.count - 1 } : entry.item))
    .sort((a, b) => a.id - b.id);

  return {
    ok: true,
    tool: "burp_get_history",
    meta: {
      source_count: sourceItems.length,
      returned_count: payload.count,
      deduped_count: items.length,
      history_size: payload.history_size,
    },
    items,
  };
}

export function summarizeRepeater(payload: BionicLinkRepeaterResponse, opts?: TspOptions): TspRepeaterSummary {
  const rawEnabled = Boolean(opts?.unfiltered) && isBurpRawDataEnabled();
  const responseHeaders = payload.response_headers || [];
  const respType = getHeader(responseHeaders, "content-type");
  const location = getHeader(responseHeaders, "location");
  const setCookieNames = cookieNamesFromSetCookie(responseHeaders);
  const bodyPreview = rawEnabled ? undefined : summarizeBody(respType, undefined, payload.response_body);

  const base: TspRepeaterSummary = {
    ok: true,
    tool: "burp_analyze_request",
    url: payload.url,
    method: payload.method,
    in_scope: payload.in_scope,
    status: payload.status,
    resp_len: payload.response_len,
    resp_type: respType ? respType.split(";")[0]?.trim() : undefined,
    location: location || undefined,
    set_cookie_names: setCookieNames,
    body_preview: bodyPreview,
  };

  if (!rawEnabled) return base;

  return {
    ...base,
    request_headers: payload.request_headers || [],
    request_body: payload.request_body,
    response_headers: payload.response_headers || [],
    response_body: payload.response_body,
  };
}

export function summarizeScan(payload: BionicLinkScanResponse): TspScanSummary {
  return {
    ok: true,
    tool: "burp_active_scan",
    url: payload.url,
    method: payload.method,
    in_scope: payload.in_scope,
    status_message: payload.status_message,
    insertion_point_count: payload.insertion_point_count,
  };
}

export function normalizeTargetUrl(input: string): string {
  const trimmed = input.trim();
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported URL protocol: ${trimmed}`);
  }
  return parsed.toString();
}
