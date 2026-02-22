package com.openclaw.bioniclink;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public final class BionicExtension implements BurpExtension {
    private static final int DEFAULT_PORT = 8090;

    private MontoyaApi api;
    private BionicServer server;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("BionicLink");

        int port = DEFAULT_PORT;
        String envPort = System.getenv("BIONICLINK_PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                port = Integer.parseInt(envPort.trim());
            } catch (NumberFormatException ignored) {
                api.logging().logToError("[BionicLink] Invalid BIONICLINK_PORT env var; using default " + DEFAULT_PORT);
                port = DEFAULT_PORT;
            }
        }

        this.server = new BionicServer(api);
        try {
            server.start(port);
            api.logging().logToOutput("[BionicLink] Server started on https://127.0.0.1:" + port);
        } catch (Exception e) {
            api.logging().logToError("[BionicLink] Failed to start server on port " + port + ": " + e.getMessage());
        }

        api.extension().registerUnloadingHandler(() -> {
            try {
                if (server != null) {
                    server.stop();
                }
                api.logging().logToOutput("[BionicLink] Server stopped.");
            } catch (Exception e) {
                api.logging().logToError("[BionicLink] Failed to stop server: " + e.getMessage());
            }
        });
    }
}
