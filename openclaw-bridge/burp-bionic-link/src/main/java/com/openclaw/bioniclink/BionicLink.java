package com.openclaw.bioniclink;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Telemetry-only client for exporting in-scope HTTP request/response pairs to the local OpenClaw bridge.
 *
 * Safety:
 * - Never blocks Burp UI threads (async executor).
 * - Only exports items in suite-wide Target Scope.
 * - Only exports traffic from PROXY and SCANNER tools.
 * - Fails closed (drops) when queue is full; logs to stdout.
 */
public final class BionicLink implements HttpHandler {
    private static final String DEFAULT_INGEST_URL = "http://127.0.0.1:8787/bionic-ingest";
    private static final int DEFAULT_MAX_BODY_BYTES = 64 * 1024;
    private static final int DEFAULT_QUEUE_SIZE = 256;
    private static final int DEFAULT_THREADS = 2;

    private final MontoyaApi api;
    private final Gson gson;
    private final String ingestUrl;
    private final boolean enabled;
    private final int maxBodyBytes;

    private ThreadPoolExecutor executor;
    private HttpClient httpClient;
    private Registration registration;
    private final AtomicLong lastErrorLogMs = new AtomicLong(0);

    public BionicLink(MontoyaApi api) {
        this.api = Objects.requireNonNull(api);
        this.gson = new Gson();
        this.ingestUrl = resolveIngestUrl();
        this.enabled = resolveEnabled();
        this.maxBodyBytes = resolveMaxBodyBytes();
    }

    public void start() {
        if (!enabled) {
            api.logging().logToOutput("[BionicLink] Telemetry disabled (BIONICLINK_INGEST_ENABLED=false).");
            return;
        }

        if (executor != null) {
            return;
        }

        executor = new ThreadPoolExecutor(
                DEFAULT_THREADS,
                DEFAULT_THREADS,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE),
                new NamedDaemonThreadFactory("bioniclink-ingest"),
                (r, ex) -> {
                    // Drop when saturated; do not impact Burp responsiveness.
                    rateLimitedStdout("[BionicLink] Telemetry queue full; dropping ingest task.");
                }
        );

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .executor(executor)
                .build();

        registration = api.http().registerHttpHandler(this);
        api.logging().logToOutput("[BionicLink] Telemetry enabled -> POST " + ingestUrl);
    }

    public void stop() {
        try {
            if (registration != null) {
                registration.deregister();
            }
        } catch (Exception ignored) {
            // ignore
        } finally {
            registration = null;
        }

        try {
            if (executor != null) {
                executor.shutdown();
                executor.awaitTermination(500, TimeUnit.MILLISECONDS);
                executor.shutdownNow();
            }
        } catch (Exception ignored) {
            // ignore
        } finally {
            executor = null;
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Telemetry is sent on response (pairs). Never modify traffic.
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!enabled || executor == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        try {
            if (!responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.SCANNER)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            HttpRequest req = responseReceived.initiatingRequest();
            if (req == null || !req.isInScope()) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            JsonObject payload = buildPayload(req, responseReceived);
            String json = gson.toJson(payload);

            submitIngest(json);
        } catch (Exception ignored) {
            // Never throw from Burp handlers.
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private JsonObject buildPayload(HttpRequest req, HttpResponse resp) {
        JsonObject obj = new JsonObject();

        String url = safeString(req.url());
        String method = safeString(req.method());
        obj.addProperty("url", url);
        obj.addProperty("method", method);

        JsonArray reqHeaders = new JsonArray();
        for (HttpHeader h : req.headers()) {
            String name = safeString(h.name());
            if (name.isBlank()) {
                continue;
            }
            String value = safeString(h.value());
            reqHeaders.add(name + ": " + value);
        }
        obj.add("request_headers", reqHeaders);

        byte[] reqBody = safeBytes(req.body() != null ? req.body().getBytes() : null);
        byte[] reqBodySlice = slice(reqBody, maxBodyBytes);
        obj.addProperty("request_body_base64", Base64.getEncoder().encodeToString(reqBodySlice));
        obj.addProperty("request_body_len", reqBody.length);
        obj.addProperty("request_body_truncated", reqBody.length > reqBodySlice.length);

        JsonArray respHeaders = new JsonArray();
        for (HttpHeader h : resp.headers()) {
            String name = safeString(h.name());
            if (name.isBlank()) {
                continue;
            }
            String value = safeString(h.value());
            respHeaders.add(name + ": " + value);
        }
        obj.add("response_headers", respHeaders);

        byte[] respBody = safeBytes(resp.body() != null ? resp.body().getBytes() : null);
        byte[] respBodySlice = slice(respBody, maxBodyBytes);
        obj.addProperty("response_body_base64", Base64.getEncoder().encodeToString(respBodySlice));
        obj.addProperty("response_body_len", respBody.length);
        obj.addProperty("response_body_truncated", respBody.length > respBodySlice.length);

        try {
            obj.addProperty("status", (int) resp.statusCode());
        } catch (Exception ignored) {
            obj.addProperty("status", 0);
        }

        try {
            obj.addProperty("in_scope", true);
        } catch (Exception ignored) {
            // ignore
        }

        return obj;
    }

    private void submitIngest(String json) {
        try {
            executor.execute(() -> postJson(json));
        } catch (RejectedExecutionException ignored) {
            // Queue full; drop.
        }
    }

    private void postJson(String json) {
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(ingestUrl))
                    .timeout(Duration.ofSeconds(2))
                    .header("Content-Type", "application/json")
                    .POST(BodyPublishers.ofString(json))
                    .build();

            httpClient.send(req, BodyHandlers.discarding());
        } catch (Exception e) {
            rateLimitedStdout("[BionicLink] Bridge ingest failed (offline?): " + e.getMessage());
        }
    }

    private void rateLimitedStdout(String msg) {
        long now = System.currentTimeMillis();
        long prev = lastErrorLogMs.get();
        if (now - prev < 10_000) {
            return;
        }
        if (!lastErrorLogMs.compareAndSet(prev, now)) {
            return;
        }
        System.out.println(msg);
    }

    private static String safeString(String value) {
        return value == null ? "" : value;
    }

    private static byte[] safeBytes(byte[] value) {
        return value == null ? new byte[0] : value;
    }

    private static byte[] slice(byte[] value, int maxBytes) {
        if (value.length <= maxBytes) {
            return value;
        }
        byte[] out = new byte[maxBytes];
        System.arraycopy(value, 0, out, 0, maxBytes);
        return out;
    }

    private static String resolveIngestUrl() {
        String raw = firstNonBlank(
                System.getenv("BIONICLINK_INGEST_URL"),
                System.getenv("OPENCLAW_BRIDGE_INGEST_URL"),
                System.getenv("OPENCLAW_BRIDGE_BASE_URL"),
                System.getenv("BRIDGE_BASE_URL")
        );

        if (raw == null || raw.isBlank()) {
            return DEFAULT_INGEST_URL;
        }

        String trimmed = raw.trim().replaceAll("/+$", "");
        if (trimmed.endsWith("/bionic-ingest")) {
            return trimmed;
        }
        return trimmed + "/bionic-ingest";
    }

    private static boolean resolveEnabled() {
        String raw = firstNonBlank(System.getenv("BIONICLINK_INGEST_ENABLED"), System.getenv("OPENCLAW_BIONIC_INGEST_ENABLED"));
        if (raw == null || raw.isBlank()) {
            return true;
        }
        String norm = raw.trim().toLowerCase();
        return norm.equals("1") || norm.equals("true") || norm.equals("yes") || norm.equals("on");
    }

    private static int resolveMaxBodyBytes() {
        String raw = firstNonBlank(System.getenv("BIONICLINK_INGEST_MAX_BODY_BYTES"), System.getenv("OPENCLAW_INGEST_MAX_BODY_BYTES"));
        if (raw == null || raw.isBlank()) {
            return DEFAULT_MAX_BODY_BYTES;
        }
        try {
            int parsed = Integer.parseInt(raw.trim());
            return parsed > 0 ? parsed : DEFAULT_MAX_BODY_BYTES;
        } catch (NumberFormatException ignored) {
            return DEFAULT_MAX_BODY_BYTES;
        }
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static final class NamedDaemonThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicLong seq = new AtomicLong(0);

        NamedDaemonThreadFactory(String prefix) {
            this.prefix = prefix == null ? "thread" : prefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName(prefix + "-" + seq.incrementAndGet());
            return t;
        }
    }
}

