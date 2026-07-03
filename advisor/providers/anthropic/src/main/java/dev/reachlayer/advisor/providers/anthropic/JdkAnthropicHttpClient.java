package dev.reachlayer.advisor.providers.anthropic;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** Real {@link AnthropicHttpClient} implementation backed by the JDK's {@link HttpClient}. */
public final class JdkAnthropicHttpClient implements AnthropicHttpClient {

    private final HttpClient httpClient;

    public JdkAnthropicHttpClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public JdkAnthropicHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String post(String url, Map<String, String> headers, String jsonBody) throws IOException {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .timeout(Duration.ofSeconds(60));
        headers.forEach(requestBuilder::header);
        HttpRequest request = requestBuilder.build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                throw new IOException("POST " + url + " returned HTTP " + status + ": " + response.body());
            }
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while calling " + url, e);
        }
    }
}
