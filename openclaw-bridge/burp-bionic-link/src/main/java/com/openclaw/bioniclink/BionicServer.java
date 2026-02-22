package com.openclaw.bioniclink;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;

final class BionicServer {
    private static final int BACKLOG = 0;
    private static final int MAX_BODY_CHARS = 8192;

    private final MontoyaApi api;
    private final Gson gson;

    private HttpServer server;

    BionicServer(MontoyaApi api) {
        this.api = Objects.requireNonNull(api);
        this.gson = new Gson();
    }

    void start(int port) throws IOException {
        if (server != null) {
            return;
        }

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), BACKLOG);
        server.createContext("/health", new HealthHandler());
        server.createContext("/history", new HistoryHandler());
        server.createContext("/scope", new ScopeHandler());
        server.createContext("/repeater", new RepeaterHandler());
        server.createContext("/scan", new ScanHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    void stop() {
        if (server == null) {
            return;
        }
        server.stop(0);
        server = null;
    }

    private void sendJson(HttpExchange exchange, int statusCode, JsonElement payload) throws IOException {
        byte[] body = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Headers", "content-type");
        headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        exchange.sendResponseHeaders(statusCode, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    private void sendError(HttpExchange exchange, int statusCode, String message) throws IOException {
        JsonObject obj = new JsonObject();
        obj.addProperty("ok", false);
        obj.addProperty("error", message);
        sendJson(exchange, statusCode, obj);
    }

    private void handleOptions(HttpExchange exchange) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Headers", "content-type");
        headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        exchange.sendResponseHeaders(204, -1);
        exchange.close();
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            byte[] bytes = is.readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseQueryParams(URI uri) {
        Map<String, String> params = new LinkedHashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isBlank()) {
            return params;
        }
        for (String part : raw.split("&")) {
            if (part.isBlank()) {
                continue;
            }
            int eq = part.indexOf('=');
            if (eq < 0) {
                params.put(urlDecode(part), "");
            } else {
                params.put(urlDecode(part.substring(0, eq)), urlDecode(part.substring(eq + 1)));
            }
        }
        return params;
    }

    private static String urlDecode(String value) {
        try {
            return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static boolean parseBoolOrDefault(String value, boolean defaultValue) {
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        String normalized = value.trim().toLowerCase();
        return normalized.equals("1") || normalized.equals("true") || normalized.equals("yes");
    }

    private static boolean isBinaryMimeType(MimeType mimeType) {
        if (mimeType == null) {
            return true;
        }
        return switch (mimeType) {
            case HTML, PLAIN_TEXT, CSS, SCRIPT, JSON, RTF, XML, YAML -> false;
            default -> true;
        };
    }

    private static String truncate(String input, int maxChars) {
        if (input == null) {
            return "";
        }
        if (input.length() <= maxChars) {
            return input;
        }
        return input.substring(0, Math.max(0, maxChars)) + "...<truncated>";
    }

    private static JsonArray headersToJson(List<HttpHeader> headers) {
        JsonArray arr = new JsonArray();
        if (headers == null) {
            return arr;
        }
        for (HttpHeader header : headers) {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", header.name());
            obj.addProperty("value", header.value());
            arr.add(obj);
        }
        return arr;
    }

    private final class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (method.equals("OPTIONS")) {
                handleOptions(exchange);
                return;
            }
            if (!method.equals("GET")) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            JsonObject obj = new JsonObject();
            obj.addProperty("ok", true);
            obj.addProperty("service", "bioniclink");
            obj.addProperty("timestamp", ZonedDateTime.now().toString());
            sendJson(exchange, 200, obj);
        }
    }

    private final class ScopeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (method.equals("OPTIONS")) {
                handleOptions(exchange);
                return;
            }
            if (!method.equals("GET")) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange.getRequestURI());
            String url = params.getOrDefault("url", "").trim();
            if (url.isBlank()) {
                sendError(exchange, 400, "Missing required query param: url");
                return;
            }

            boolean inScope = api.scope().isInScope(url);
            JsonObject obj = new JsonObject();
            obj.addProperty("ok", true);
            obj.addProperty("url", url);
            obj.addProperty("in_scope", inScope);
            sendJson(exchange, 200, obj);
        }
    }

    private final class HistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (method.equals("OPTIONS")) {
                handleOptions(exchange);
                return;
            }
            if (!method.equals("GET")) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            Map<String, String> params = parseQueryParams(exchange.getRequestURI());
            int limit = parseIntOrDefault(params.get("limit"), 20);
            int fromId = parseIntOrDefault(params.get("fromId"), 0);
            boolean inScopeOnly = parseBoolOrDefault(params.get("inScope"), false);

            if (limit < 1) {
                limit = 1;
            }
            if (limit > 200) {
                limit = 200;
            }
            if (fromId < 0) {
                fromId = 0;
            }

            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int size = history.size();

            // IDs are 1-based sequence numbers derived from the full proxy history ordering.
            List<JsonObject> selected = new ArrayList<>();

            if (fromId > 0) {
                int startIndex = Math.min(size, fromId); // fromId == last-seen id
                for (int i = startIndex; i < size; i++) {
                    ProxyHttpRequestResponse entry = history.get(i);
                    boolean inScope = entry.request().isInScope();
                    if (inScopeOnly && !inScope) {
                        continue;
                    }
                    selected.add(toHistoryJson(i + 1, entry, inScope));
                }
                // keep only last "limit"
                if (selected.size() > limit) {
                    selected = selected.subList(selected.size() - limit, selected.size());
                }
            } else {
                for (int i = size - 1; i >= 0 && selected.size() < limit; i--) {
                    ProxyHttpRequestResponse entry = history.get(i);
                    boolean inScope = entry.request().isInScope();
                    if (inScopeOnly && !inScope) {
                        continue;
                    }
                    selected.add(toHistoryJson(i + 1, entry, inScope));
                }
                // reverse to chronological order
                java.util.Collections.reverse(selected);
            }

            JsonObject response = new JsonObject();
            response.addProperty("ok", true);
            response.addProperty("count", selected.size());
            response.addProperty("history_size", size);
            JsonArray items = new JsonArray();
            for (JsonObject item : selected) {
                items.add(item);
            }
            response.add("items", items);
            sendJson(exchange, 200, response);
        }

        private JsonObject toHistoryJson(int id, ProxyHttpRequestResponse entry, boolean inScope) {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", id);
            obj.addProperty("time", entry.time().toString());
            obj.addProperty("in_scope", inScope);
            obj.addProperty("has_response", entry.hasResponse());
            obj.addProperty("mime_type", entry.mimeType() != null ? entry.mimeType().name() : "");

            HttpRequest request = entry.request();
            obj.addProperty("url", request.url());
            obj.addProperty("method", request.method());
            obj.addProperty("host", request.httpService().host());
            obj.addProperty("path", request.path());
            obj.add("request_headers", headersToJson(request.headers()));
            String requestBody = request.bodyToString();
            obj.addProperty("request_body", truncate(requestBody, MAX_BODY_CHARS));

            if (entry.hasResponse()) {
                HttpResponse response = entry.response();
                obj.addProperty("status", response.statusCode());
                obj.add("response_headers", headersToJson(response.headers()));
                obj.addProperty("response_len", response.body() != null ? response.body().length() : 0);

                String respBodyPreview = "";
                if (!isBinaryMimeType(entry.mimeType())) {
                    respBodyPreview = truncate(response.bodyToString(), MAX_BODY_CHARS);
                }
                obj.addProperty("response_body", respBodyPreview);
            } else {
                obj.addProperty("status", 0);
                obj.addProperty("response_len", 0);
                obj.add("response_headers", new JsonArray());
                obj.addProperty("response_body", "");
            }

            return obj;
        }
    }

    private final class RepeaterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (method.equals("OPTIONS")) {
                handleOptions(exchange);
                return;
            }
            if (!method.equals("POST")) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            String rawBody = readRequestBody(exchange);
            JsonObject body;
            try {
                body = JsonParser.parseString(rawBody).getAsJsonObject();
            } catch (Exception e) {
                sendError(exchange, 400, "Invalid JSON body");
                return;
            }

            String url = body.has("url") ? body.get("url").getAsString().trim() : "";
            String reqMethod = body.has("method") ? body.get("method").getAsString().trim() : "GET";
            JsonObject headers = body.has("headers") && body.get("headers").isJsonObject() ? body.getAsJsonObject("headers") : new JsonObject();
            String reqBody = body.has("body") ? body.get("body").getAsString() : "";

            if (url.isBlank()) {
                sendError(exchange, 400, "url is required");
                return;
            }

            if (!api.scope().isInScope(url)) {
                sendError(exchange, 403, "Target URL is out of scope.");
                return;
            }

            HttpRequest request = HttpRequest.httpRequestFromUrl(url).withMethod(reqMethod);
            for (Map.Entry<String, JsonElement> entry : headers.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue() != null ? entry.getValue().getAsString() : "";
                if (name != null && !name.isBlank()) {
                    request = request.withAddedHeader(name, value);
                }
            }
            if (reqBody != null && !reqBody.isBlank()) {
                request = request.withBody(reqBody);
            }

            HttpRequestResponse rr = api.http().sendRequest(request);
            HttpResponse response = rr.response();

            JsonObject out = new JsonObject();
            out.addProperty("ok", true);
            out.addProperty("url", request.url());
            out.addProperty("method", request.method());
            out.addProperty("in_scope", request.isInScope());
            out.add("request_headers", headersToJson(request.headers()));
            out.addProperty("request_body", truncate(request.bodyToString(), MAX_BODY_CHARS));

            if (response != null) {
                out.addProperty("status", response.statusCode());
                out.add("response_headers", headersToJson(response.headers()));
                out.addProperty("response_len", response.body() != null ? response.body().length() : 0);
                out.addProperty("response_body", truncate(response.bodyToString(), MAX_BODY_CHARS));
            } else {
                out.addProperty("status", 0);
                out.add("response_headers", new JsonArray());
                out.addProperty("response_len", 0);
                out.addProperty("response_body", "");
            }

            sendJson(exchange, 200, out);
        }
    }

    private final class ScanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (method.equals("OPTIONS")) {
                handleOptions(exchange);
                return;
            }
            if (!method.equals("POST")) {
                sendError(exchange, 405, "Method not allowed");
                return;
            }

            String rawBody = readRequestBody(exchange);
            JsonObject body;
            try {
                body = JsonParser.parseString(rawBody).getAsJsonObject();
            } catch (Exception e) {
                sendError(exchange, 400, "Invalid JSON body");
                return;
            }

            int requestId = body.has("requestId") ? body.get("requestId").getAsInt() : 0;
            String url = body.has("url") ? body.get("url").getAsString().trim() : "";
            String reqMethod = body.has("method") ? body.get("method").getAsString().trim() : "GET";

            HttpRequest request;
            if (requestId > 0) {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                int index = requestId - 1;
                if (index < 0 || index >= history.size()) {
                    sendError(exchange, 404, "requestId not found in proxy history");
                    return;
                }
                ProxyHttpRequestResponse item = history.get(index);
                request = item.finalRequest();
                url = request.url();
            } else {
                if (url.isBlank()) {
                    sendError(exchange, 400, "url is required (or provide requestId)");
                    return;
                }
                request = HttpRequest.httpRequestFromUrl(url).withMethod(reqMethod);
            }

            boolean inScope = api.scope().isInScope(url);
            if (!inScope) {
                sendError(exchange, 403, "Target URL is out of scope.");
                return;
            }

            Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            audit.addRequest(request);

            JsonObject out = new JsonObject();
            out.addProperty("ok", true);
            out.addProperty("url", url);
            out.addProperty("method", request.method());
            out.addProperty("in_scope", true);
            out.addProperty("status_message", audit.statusMessage());
            out.addProperty("request_count", audit.requestCount());
            out.addProperty("insertion_point_count", audit.insertionPointCount());

            sendJson(exchange, 200, out);
        }
    }
}
