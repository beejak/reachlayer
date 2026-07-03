package dev.reachlayer.advisor.providers.anthropic;

import java.io.IOException;
import java.util.Map;

/**
 * Minimal HTTP abstraction so {@link AnthropicLlmProvider} is unit-testable without live network
 * calls. Production code uses {@link JdkAnthropicHttpClient}; tests can supply a lambda returning
 * a canned JSON response.
 */
public interface AnthropicHttpClient {

    /**
     * Performs a {@code POST} request against {@code url} with the given headers and JSON body,
     * returning the response body as a string.
     *
     * @throws IOException if the request fails at the transport level or the server responds
     *     with a non-2xx status code
     */
    String post(String url, Map<String, String> headers, String jsonBody) throws IOException;
}
