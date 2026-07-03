package dev.reachlayer.enrich.kev;

import java.io.IOException;
import java.net.URI;

/**
 * Minimal HTTP abstraction so {@link KevClient} is unit-testable without live network calls.
 * Production code uses {@link JdkHttpFetcher}; tests can supply a lambda returning canned JSON.
 *
 * <p>Deliberately duplicated from {@code enrich:epss}'s identically-shaped interface rather than
 * shared, so the two enrich modules stay decoupled from each other (see PLAN.md §7 module list).
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
