package dev.reachlayer.enrich.epss;

import java.io.IOException;
import java.net.URI;

/**
 * Minimal HTTP abstraction so {@link EpssClient} is unit-testable without live network calls.
 * Production code uses {@link JdkHttpFetcher}; tests can supply a lambda returning canned JSON.
 */
public interface HttpFetcher {

    /**
     * Performs a GET request against {@code uri} and returns the response body as a string.
     *
     * @throws IOException if the request fails at the transport level or the server responds
     *     with a non-2xx status code.
     */
    String fetch(URI uri) throws IOException;
}
