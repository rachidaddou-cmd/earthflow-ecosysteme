package com.earthflow.sdk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Earthflow Écosystème — Java SDK v2.0.0
 */
public class EarthflowClient {

    private final String apiKey;
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    private EarthflowClient(Builder builder) {
        this.apiKey = builder.apiKey;
        this.baseUrl = builder.baseUrl.replaceAll("/$", "");
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    private String post(String path, Object body) throws Exception {
        String json = mapper.writeValueAsString(body);
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("Content-Type", "application/json")
            .header("X-API-Key", apiKey)
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .timeout(Duration.ofSeconds(10))
            .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new RuntimeException("HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return resp.body();
    }

    private String get(String path) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + path))
            .header("X-API-Key", apiKey)
            .GET()
            .timeout(Duration.ofSeconds(10))
            .build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        return resp.body();
    }

    /** Submit a request through the Earthflow governance proxy */
    public Map<?, ?> proxy(ProxyRequest request) throws Exception {
        return mapper.readValue(post("/v1/proxy", request), Map.class);
    }

    /** Health check */
    public Map<?, ?> health() throws Exception {
        return mapper.readValue(get("/health"), Map.class);
    }

    public static class Builder {
        private String apiKey;
        private String baseUrl = "https://localhost:8443";

        public Builder apiKey(String apiKey) { this.apiKey = apiKey; return this; }
        public Builder baseUrl(String baseUrl) { this.baseUrl = baseUrl; return this; }
        public EarthflowClient build() {
            if (apiKey == null || apiKey.isBlank()) throw new IllegalArgumentException("apiKey required");
            return new EarthflowClient(this);
        }
    }

    public static class ProxyRequest {
        public String model;
        public Object[] messages;
        public Map<String, Object> metadata;

        public ProxyRequest(String model, Object[] messages) {
            this.model = model;
            this.messages = messages;
        }
    }
}
