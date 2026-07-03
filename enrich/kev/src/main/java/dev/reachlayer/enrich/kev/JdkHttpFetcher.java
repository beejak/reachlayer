package dev.reachlayer.enrich.kev;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Real {@link HttpFetcher} implementation backed by the JDK's {@link HttpClient}. */
public final class JdkHttpFetcher implements HttpFetcher {

    private final HttpClient httpClient;

    public JdkHttpFetcher() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public JdkHttpFetcher(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String fetch(URI uri) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json")
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                throw new IOException("GET " + uri + " returned HTTP " + status);
            }
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while fetching " + uri, e);
        }
    }
}
