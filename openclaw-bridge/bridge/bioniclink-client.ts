import { URL } from "node:url";

export interface BionicLinkHeader {
  name: string;
  value: string;
}

export interface BionicLinkHistoryItem {
  id: number;
  time: string;
  url: string;
  method: string;
  host: string;
  path: string;
  in_scope: boolean;
  has_response: boolean;
  mime_type: string;
  request_headers: BionicLinkHeader[];
  request_body: string;
  status: number;
  response_headers: BionicLinkHeader[];
  response_len: number;
  response_body: string;
}

export interface BionicLinkHistoryResponse {
  ok: boolean;
  count: number;
  history_size: number;
  items: BionicLinkHistoryItem[];
}

export interface BionicLinkScopeResponse {
  ok: boolean;
  url: string;
  in_scope: boolean;
}

export interface BionicLinkRepeaterRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface BionicLinkRepeaterResponse {
  ok: boolean;
  url: string;
  method: string;
  in_scope: boolean;
  request_headers: BionicLinkHeader[];
  request_body: string;
  status: number;
  response_headers: BionicLinkHeader[];
  response_len: number;
  response_body: string;
}

export interface BionicLinkScanRequest {
  url?: string;
  method?: string;
  requestId?: number;
}

export interface BionicLinkScanResponse {
  ok: boolean;
  url: string;
  method: string;
  in_scope: boolean;
  status_message: string;
  request_count: number;
  insertion_point_count: number;
}

export interface BionicLinkHealthResponse {
  ok: boolean;
  service: string;
  timestamp: string;
}

async function fetchJson<T>(
  url: string,
  options: RequestInit,
  timeoutMs: number,
): Promise<{ status: number; data: T }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const text = await res.text();
    let data: T;
    try {
      data = JSON.parse(text) as T;
    } catch {
      throw new Error(`BionicLink returned non-JSON (${res.status}): ${text.slice(0, 500)}`);
    }
    return { status: res.status, data };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`BionicLink timeout after ${timeoutMs}ms: ${url}`);
    }

    // Node's fetch throws a generic TypeError('fetch failed') with a useful `cause`.
    const cause = typeof error === "object" && error !== null && "cause" in error ? (error as { cause?: unknown }).cause : undefined;
    const causeCode =
      typeof cause === "object" && cause !== null && "code" in cause ? String((cause as { code?: unknown }).code || "") : "";
    const causeMessage = cause instanceof Error ? cause.message : cause ? String(cause) : "";

    const detail = [causeCode, causeMessage].filter(Boolean).join(" ");
    throw new Error(`BionicLink request failed: ${url}${detail ? ` (${detail})` : ""}`);
  } finally {
    clearTimeout(timeout);
  }
}

function joinUrl(baseUrl: string, pathname: string): string {
  const base = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
  return new URL(pathname.replace(/^\//, ""), base).toString();
}

export async function bioniclinkHealth(baseUrl: string, timeoutMs: number): Promise<BionicLinkHealthResponse> {
  const url = joinUrl(baseUrl, "/health");
  const { data } = await fetchJson<BionicLinkHealthResponse>(url, { method: "GET" }, timeoutMs);
  return data;
}

export async function bioniclinkScopeCheck(baseUrl: string, targetUrl: string, timeoutMs: number): Promise<BionicLinkScopeResponse> {
  const url = new URL(joinUrl(baseUrl, "/scope"));
  url.searchParams.set("url", targetUrl);
  const { data } = await fetchJson<BionicLinkScopeResponse>(url.toString(), { method: "GET" }, timeoutMs);
  return data;
}

export async function bioniclinkGetHistory(
  baseUrl: string,
  params: { limit?: number; fromId?: number; inScope?: boolean },
  timeoutMs: number,
): Promise<BionicLinkHistoryResponse> {
  const url = new URL(joinUrl(baseUrl, "/history"));
  if (typeof params.limit === "number") url.searchParams.set("limit", String(params.limit));
  if (typeof params.fromId === "number") url.searchParams.set("fromId", String(params.fromId));
  if (typeof params.inScope === "boolean") url.searchParams.set("inScope", params.inScope ? "true" : "false");
  const { data } = await fetchJson<BionicLinkHistoryResponse>(url.toString(), { method: "GET" }, timeoutMs);
  return data;
}

export async function bioniclinkRepeater(
  baseUrl: string,
  payload: BionicLinkRepeaterRequest,
  timeoutMs: number,
): Promise<BionicLinkRepeaterResponse> {
  const url = joinUrl(baseUrl, "/repeater");
  const { data } = await fetchJson<BionicLinkRepeaterResponse>(
    url,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    timeoutMs,
  );
  return data;
}

export async function bioniclinkScan(baseUrl: string, payload: BionicLinkScanRequest, timeoutMs: number): Promise<BionicLinkScanResponse> {
  const url = joinUrl(baseUrl, "/scan");
  const { data } = await fetchJson<BionicLinkScanResponse>(
    url,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
    timeoutMs,
  );
  return data;
}
