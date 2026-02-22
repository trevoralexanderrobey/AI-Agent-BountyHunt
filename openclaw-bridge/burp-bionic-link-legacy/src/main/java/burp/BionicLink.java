package burp;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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
 * Telemetry-only Burp extension that forwards in-scope Proxy + Scanner traffic to the local OpenClaw bridge.
 *
 * Expected ingest endpoint:
 * - POST https://127.0.0.1:8787/bionic-ingest
 *
 * Safety:
 * - Never blocks Burp UI threads (async executor + bounded queue).
 * - Only exports items in suite-wide Target Scope.
 * - Only exports traffic from PROXY and SCANNER tools.
 * - Fails closed (drops) when queue is full or bridge is offline; logs to output/stdout.
 */
public class BionicLink implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private static final String DEFAULT_INGEST_URL = "https://127.0.0.1:8787/bionic-ingest";
    private static final int DEFAULT_MAX_BODY_BYTES = 64 * 1024;
    private static final int DEFAULT_QUEUE_SIZE = 256;
    private static final int DEFAULT_THREADS = 2;
    private static final int DEFAULT_TIMEOUT_MS = 2_000;

    private final AtomicLong lastErrorLogMs = new AtomicLong(0);

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private Gson gson;

    private String ingestUrl;
    private boolean enabled;
    private int maxBodyBytes;

    private ThreadPoolExecutor executor;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = Objects.requireNonNull(callbacks);
        this.helpers = callbacks.getHelpers();
        this.gson = new Gson();

        callbacks.setExtensionName("BionicLink");

        this.ingestUrl = resolveIngestUrl();
        this.enabled = resolveEnabled();
        this.maxBodyBytes = resolveMaxBodyBytes();

        if (!enabled) {
            log("[BionicLink] Telemetry disabled (BIONICLINK_INGEST_ENABLED=false).");
            return;
        }

        executor = new ThreadPoolExecutor(
                DEFAULT_THREADS,
                DEFAULT_THREADS,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE),
                new NamedDaemonThreadFactory("bioniclink-ingest"),
                (r, ex) -> rateLimitedLog("[BionicLink] Telemetry queue full; dropping ingest task.")
        );

        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
        log("[BionicLink] Telemetry enabled -> POST " + ingestUrl);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!enabled || executor == null) {
            return;
        }

        // Only send on response so we have a request/response pair.
        if (messageIsRequest) {
            return;
        }

        // Only proxy + scanner tools.
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_SCANNER) {
            return;
        }

        if (messageInfo == null) {
            return;
        }

        try {
            byte[] reqBytes = messageInfo.getRequest();
            if (reqBytes == null || reqBytes.length == 0) {
                return;
            }

            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            URL url = reqInfo.getUrl();
            if (url == null || !callbacks.isInScope(url)) {
                return;
            }

            JsonObject payload = new JsonObject();
            payload.addProperty("url", url.toString());
            payload.addProperty("method", safeString(reqInfo.getMethod()));

            JsonArray reqHeaders = new JsonArray();
            List<String> reqHeaderLines = reqInfo.getHeaders();
            // Burp includes the request line as index 0; the bridge expects only headers.
            for (int i = 1; i < reqHeaderLines.size(); i++) {
                reqHeaders.add(reqHeaderLines.get(i));
            }
            payload.add("request_headers", reqHeaders);

            byte[] reqBody = sliceBody(reqBytes, reqInfo.getBodyOffset(), maxBodyBytes);
            payload.addProperty("request_body_base64", Base64.getEncoder().encodeToString(reqBody));

            byte[] respBytes = messageInfo.getResponse();
            if (respBytes != null && respBytes.length > 0) {
                IResponseInfo respInfo = helpers.analyzeResponse(respBytes);

                JsonArray respHeaders = new JsonArray();
                List<String> respHeaderLines = respInfo.getHeaders();
                // Burp includes the status line as index 0; the bridge expects only headers.
                for (int i = 1; i < respHeaderLines.size(); i++) {
                    respHeaders.add(respHeaderLines.get(i));
                }
                payload.add("response_headers", respHeaders);

                byte[] respBody = sliceBody(respBytes, respInfo.getBodyOffset(), maxBodyBytes);
                payload.addProperty("response_body_base64", Base64.getEncoder().encodeToString(respBody));
            }

            String json = gson.toJson(payload);
            submitIngest(json);
        } catch (Exception ignored) {
            // Never throw from Burp listeners.
        }
    }

    @Override
    public void extensionUnloaded() {
        enabled = false;

        try {
            if (callbacks != null) {
                try {
                    callbacks.removeHttpListener(this);
                } catch (Exception ignored) {
                    // ignore
                }
            }
        } finally {
            // ignore
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

    private void submitIngest(String json) {
        try {
            executor.execute(() -> postJson(json));
        } catch (RejectedExecutionException ignored) {
            // Queue full; drop.
        }
    }

    private void postJson(String json) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(ingestUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT_MS);
            conn.setReadTimeout(DEFAULT_TIMEOUT_MS);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");

            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bytes.length);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bytes);
            }

            // Trigger the request and drain the response quietly.
            try {
                conn.getInputStream().close();
            } catch (Exception ignored) {
                try {
                    if (conn.getErrorStream() != null) {
                        conn.getErrorStream().close();
                    }
                } catch (Exception ignored2) {
                    // ignore
                }
            }
        } catch (Exception e) {
            rateLimitedLog("[BionicLink] Bridge ingest failed (offline?): " + e.getMessage());
        } finally {
            if (conn != null) {
                try {
                    conn.disconnect();
                } catch (Exception ignored) {
                    // ignore
                }
            }
        }
    }

    private void log(String msg) {
        if (callbacks != null) {
            try {
                callbacks.printOutput(msg);
                return;
            } catch (Exception ignored) {
                // ignore
            }
        }
        System.out.println(msg);
    }

    private void rateLimitedLog(String msg) {
        long now = System.currentTimeMillis();
        long prev = lastErrorLogMs.get();
        if (now - prev < 10_000) {
            return;
        }
        if (!lastErrorLogMs.compareAndSet(prev, now)) {
            return;
        }
        log(msg);
    }

    private static String safeString(String value) {
        return value == null ? "" : value;
    }

    private static byte[] sliceBody(byte[] msg, int bodyOffset, int maxBytes) {
        if (msg == null) {
            return new byte[0];
        }
        int start = Math.max(0, bodyOffset);
        if (start >= msg.length) {
            return new byte[0];
        }
        int available = msg.length - start;
        int take = Math.min(available, Math.max(0, maxBytes));
        byte[] out = new byte[take];
        System.arraycopy(msg, start, out, 0, take);
        return out;
    }

    private static String resolveIngestUrl() {
        String raw = firstNonBlank(
                System.getenv("BIONICLINK_INGEST_URL"),
                System.getenv("OPENCLAW_BRIDGE_INGEST_URL"),
                System.getenv("OPENCLAW_BRIDGE_BASE_URL"),
                System.getenv("BRIDGE_BASE_URL")
        );

        if (raw == null || raw.trim().isEmpty()) {
            return DEFAULT_INGEST_URL;
        }

        String trimmed = raw.trim().replaceAll("/+$", "");
        if (trimmed.endsWith("/bionic-ingest")) {
            return trimmed;
        }
        return trimmed + "/bionic-ingest";
    }

    private static boolean resolveEnabled() {
        String raw = firstNonBlank(
                System.getenv("BIONICLINK_INGEST_ENABLED"),
                System.getenv("OPENCLAW_BIONIC_INGEST_ENABLED")
        );
        if (raw == null || raw.trim().isEmpty()) {
            return true;
        }
        String norm = raw.trim().toLowerCase();
        return norm.equals("1") || norm.equals("true") || norm.equals("yes") || norm.equals("on");
    }

    private static int resolveMaxBodyBytes() {
        String raw = firstNonBlank(
                System.getenv("BIONICLINK_INGEST_MAX_BODY_BYTES"),
                System.getenv("OPENCLAW_INGEST_MAX_BODY_BYTES")
        );
        if (raw == null || raw.trim().isEmpty()) {
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
            if (value != null && !value.trim().isEmpty()) {
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

