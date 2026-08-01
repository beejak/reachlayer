package dev.reachlayer.output.githubpr;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Exercises {@link GitHubRestApiClient} against a real local HTTP server (JDK-builtin {@link
 * HttpServer}, no mocking framework, consistent with this repo's "inject the I/O boundary and
 * test against something real" convention) -- this is the one client in the repo that previously
 * had no dedicated test at all (only the interface-level {@code GitHubPrCommentRendererTest},
 * which fakes {@link GitHubApiClient} and never exercises this class's actual HTTP/pagination
 * logic).
 */
class GitHubRestApiClientTest {

    private static final int PAGE_SIZE = 100;

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** This test lives in the same package, so the package-visible 3-arg constructor is directly callable. */
    private GitHubRestApiClient clientFor(HttpServer server) {
        String base = "http://localhost:" + server.getAddress().getPort();
        return new GitHubRestApiClient("fake-token", HttpClient.newHttpClient(), base);
    }

    @Test
    void followsPaginationUntilAShortPageIsReturned() throws Exception {
        AtomicInteger requestCount = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/repos/acme/widgets/issues/42/comments", exchange -> {
            requestCount.incrementAndGet();
            String query = exchange.getRequestURI().getQuery();
            boolean isPageTwo = query != null && query.contains("page=2");
            String body = isPageTwo
                    ? "[{\"id\":9999,\"body\":\"the marker comment\"}]" // short page -> stop here
                    : fullPageOfComments(PAGE_SIZE);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        List<GitHubApiClient.ExistingComment> comments = clientFor(server).listIssueComments("acme", "widgets", 42);

        assertThat(comments).hasSize(PAGE_SIZE + 1);
        assertThat(comments).anyMatch(c -> c.id() == 9999L && c.body().equals("the marker comment"));
        assertThat(requestCount.get()).isEqualTo(2); // one full page, then the short page that stops iteration
    }

    @Test
    void singlePageOfCommentsMakesExactlyOneRequest() throws Exception {
        AtomicInteger requestCount = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/repos/acme/widgets/issues/7/comments", exchange -> {
            requestCount.incrementAndGet();
            String body = "[{\"id\":1,\"body\":\"only comment\"}]";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        List<GitHubApiClient.ExistingComment> comments = clientFor(server).listIssueComments("acme", "widgets", 7);

        assertThat(comments).hasSize(1);
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    void throwsIoExceptionOnNonSuccessStatus() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/repos/acme/widgets/issues/1/comments", exchange -> {
            byte[] bytes = "{\"message\":\"Not Found\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(404, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> clientFor(server).listIssueComments("acme", "widgets", 1))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("404");
    }

    private static String fullPageOfComments(int count) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append("{\"id\":").append(i).append(",\"body\":\"comment #").append(i).append("\"}");
        }
        return sb.append("]").toString();
    }
}
