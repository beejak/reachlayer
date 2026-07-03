package dev.reachlayer.output.githubpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Real {@link GitHubApiClient} implementation backed by the JDK's {@link HttpClient} and the
 * GitHub REST API (v2022-11-28). Only the operations needed to upsert a single issue comment are
 * implemented — this is deliberately not a general-purpose GitHub SDK.
 *
 * <p>Endpoints used:
 *
 * <ul>
 *   <li>{@code GET  /repos/{owner}/{repo}/issues/{prNumber}/comments}
 *   <li>{@code PATCH /repos/{owner}/{repo}/issues/comments/{commentId}}
 *   <li>{@code POST /repos/{owner}/{repo}/issues/{prNumber}/comments}
 * </ul>
 */
public final class GitHubRestApiClient implements GitHubApiClient {

    private static final String API_BASE = "https://api.github.com";
    private static final String API_VERSION = "2022-11-28";
    private static final int MAX_ERROR_BODY_LEN = 500;

    private final String token;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GitHubRestApiClient(String token) {
        this(token, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public GitHubRestApiClient(String token, HttpClient httpClient) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("GitHub token must not be blank");
        }
        this.token = token;
        this.httpClient = httpClient;
    }

    /**
     * Builds a client using the {@code GITHUB_TOKEN} environment variable (as set automatically by
     * GitHub Actions). Throws if the variable is absent or blank.
     */
    public static GitHubRestApiClient fromEnvironment() {
        String token = System.getenv("GITHUB_TOKEN");
        if (token == null || token.isBlank()) {
            throw new IllegalStateException(
                    "GITHUB_TOKEN environment variable is required to talk to the GitHub API but was not set");
        }
        return new GitHubRestApiClient(token);
    }

    @Override
    public List<ExistingComment> listIssueComments(String owner, String repo, int prNumber) throws IOException {
        URI uri = URI.create(API_BASE + "/repos/" + owner + "/" + repo + "/issues/" + prNumber + "/comments");
        HttpRequest request = requestBuilder(uri).GET().build();
        HttpResponse<String> response = send(request);
        requireSuccess(request.method(), uri, response);

        GhComment[] comments;
        try {
            comments = objectMapper.readValue(response.body(), GhComment[].class);
        } catch (IOException e) {
            throw new IOException("Malformed GitHub comments response for " + uri + ": " + e.getMessage(), e);
        }

        List<ExistingComment> result = new ArrayList<>(comments.length);
        for (GhComment c : comments) {
            result.add(new ExistingComment(c.id(), c.body() == null ? "" : c.body()));
        }
        return result;
    }

    @Override
    public void updateComment(String owner, String repo, long commentId, String body) throws IOException {
        URI uri = URI.create(API_BASE + "/repos/" + owner + "/" + repo + "/issues/comments/" + commentId);
        String json = toJsonBody(body);
        HttpRequest request = requestBuilder(uri)
                .method("PATCH", BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = send(request);
        requireSuccess(request.method(), uri, response);
    }

    @Override
    public void createComment(String owner, String repo, int prNumber, String body) throws IOException {
        URI uri = URI.create(API_BASE + "/repos/" + owner + "/" + repo + "/issues/" + prNumber + "/comments");
        String json = toJsonBody(body);
        HttpRequest request = requestBuilder(uri)
                .POST(BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = send(request);
        requireSuccess(request.method(), uri, response);
    }

    private HttpRequest.Builder requestBuilder(URI uri) {
        return HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", API_VERSION)
                .header("Content-Type", "application/json; charset=utf-8");
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while calling " + request.uri(), e);
        }
    }

    private void requireSuccess(String method, URI uri, HttpResponse<String> response) throws IOException {
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            String body = response.body() == null ? "" : response.body();
            String truncated = body.length() > MAX_ERROR_BODY_LEN ? body.substring(0, MAX_ERROR_BODY_LEN) + "..." : body;
            throw new IOException(method + " " + uri + " returned HTTP " + status + ": " + truncated);
        }
    }

    private String toJsonBody(String body) throws IOException {
        try {
            return objectMapper.writeValueAsString(new BodyPayload(body));
        } catch (IOException e) {
            throw new IOException("Failed to serialize comment body as JSON: " + e.getMessage(), e);
        }
    }

    /** Shape of a single entry in the GitHub "list issue comments" response (unknown fields ignored). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record GhComment(long id, String body) {
    }

    /** Request body for create/update comment: {@code {"body": "..."}}. */
    private record BodyPayload(String body) {
    }
}
