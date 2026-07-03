package dev.reachlayer.output.githubpr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class GitHubPrCommentRendererTest {

    private static final String MARKER = "<!-- reachlayer:report -->";

    @Test
    void createsNewCommentWhenNoExistingCommentHasTheMarker() throws Exception {
        FakeGitHubApiClient client = new FakeGitHubApiClient();
        client.comments.add(new GitHubApiClient.ExistingComment(1L, "some unrelated comment"));

        GitHubPrCommentRenderer renderer = new GitHubPrCommentRenderer(client, "acme", "widgets", 42, MARKER);
        renderer.render(sampleReport());

        assertThat(client.createCalls).hasSize(1);
        assertThat(client.createCalls.get(0).body()).contains(MARKER);
        assertThat(client.createCalls.get(0).prNumber()).isEqualTo(42);
        assertThat(client.updateCalls).isEmpty();
    }

    @Test
    void updatesExistingCommentInPlaceWhenMarkerAlreadyPresent() throws Exception {
        FakeGitHubApiClient client = new FakeGitHubApiClient();
        long existingId = 99L;
        client.comments.add(new GitHubApiClient.ExistingComment(existingId, "old report\n" + MARKER + "\nstale data"));

        GitHubPrCommentRenderer renderer = new GitHubPrCommentRenderer(client, "acme", "widgets", 42, MARKER);
        renderer.render(sampleReport());

        assertThat(client.updateCalls).hasSize(1);
        assertThat(client.updateCalls.get(0).commentId()).isEqualTo(existingId);
        assertThat(client.updateCalls.get(0).body()).contains(MARKER);
        assertThat(client.createCalls).isEmpty();
    }

    @Test
    void targetsTheCorrectCommentWhenMultipleCommentsExistAndOnlyOneHasTheMarker() throws Exception {
        FakeGitHubApiClient client = new FakeGitHubApiClient();
        client.comments.add(new GitHubApiClient.ExistingComment(1L, "unrelated comment #1"));
        client.comments.add(new GitHubApiClient.ExistingComment(2L, "another unrelated comment"));
        long markedId = 3L;
        client.comments.add(new GitHubApiClient.ExistingComment(markedId, MARKER + "\nprevious report"));
        client.comments.add(new GitHubApiClient.ExistingComment(4L, "yet another comment"));

        GitHubPrCommentRenderer renderer = new GitHubPrCommentRenderer(client, "acme", "widgets", 42, MARKER);
        renderer.render(sampleReport());

        assertThat(client.updateCalls).hasSize(1);
        assertThat(client.updateCalls.get(0).commentId()).isEqualTo(markedId);
        assertThat(client.createCalls).isEmpty();
    }

    @Test
    void wrapsIoExceptionFromClientAsOutputExceptionWithContext() {
        GitHubApiClient failingClient = new GitHubApiClient() {
            @Override
            public List<ExistingComment> listIssueComments(String owner, String repo, int prNumber) throws IOException {
                throw new IOException("GitHub API unavailable");
            }

            @Override
            public void updateComment(String owner, String repo, long commentId, String body) {
                throw new AssertionError("should not be called");
            }

            @Override
            public void createComment(String owner, String repo, int prNumber, String body) {
                throw new AssertionError("should not be called");
            }
        };

        GitHubPrCommentRenderer renderer = new GitHubPrCommentRenderer(failingClient, "acme", "widgets", 42, MARKER);

        assertThatThrownBy(() -> renderer.render(sampleReport()))
                .isInstanceOf(OutputException.class)
                .hasMessageContaining("acme/widgets#42")
                .hasMessageContaining("GitHub API unavailable")
                .hasCauseInstanceOf(IOException.class);
    }

    @Test
    void nameIsGithubPr() {
        GitHubPrCommentRenderer renderer =
                new GitHubPrCommentRenderer(new FakeGitHubApiClient(), "acme", "widgets", 1, MARKER);
        assertThat(renderer.name()).isEqualTo("github-pr");
    }

    @Test
    void parseOwnerRepoSplitsOnFirstSlash() {
        String[] result = GitHubPrCommentRenderer.parseOwnerRepo("acme/widgets");
        assertThat(result).containsExactly("acme", "widgets");
    }

    @Test
    void parseOwnerRepoRejectsMissingOrMalformedValues() {
        assertThatThrownBy(() -> GitHubPrCommentRenderer.parseOwnerRepo(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GITHUB_REPOSITORY");
        assertThatThrownBy(() -> GitHubPrCommentRenderer.parseOwnerRepo(""))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> GitHubPrCommentRenderer.parseOwnerRepo("no-slash-here"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("owner/repo");
    }

    @Test
    void parsePrNumberParsesValidIntegers() {
        assertThat(GitHubPrCommentRenderer.parsePrNumber("42")).isEqualTo(42);
        assertThat(GitHubPrCommentRenderer.parsePrNumber(" 7 ")).isEqualTo(7);
    }

    @Test
    void parsePrNumberRejectsMissingOrNonNumericValues() {
        assertThatThrownBy(() -> GitHubPrCommentRenderer.parsePrNumber(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GITHUB_PR_NUMBER");
        assertThatThrownBy(() -> GitHubPrCommentRenderer.parsePrNumber("not-a-number"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("integer");
    }

    private static RankedReport sampleReport() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Sample finding")
                .severity("High")
                .riskScore(75.0)
                .build();
        return RankedReport.of(List.of(finding), "acme/widgets", 5);
    }

    /** In-memory fake used instead of a mocking framework, backed by simple mutable lists. */
    private static final class FakeGitHubApiClient implements GitHubApiClient {
        final List<ExistingComment> comments = new ArrayList<>();
        final List<CreateCall> createCalls = new ArrayList<>();
        final List<UpdateCall> updateCalls = new ArrayList<>();
        final AtomicLong nextId = new AtomicLong(1000);

        @Override
        public List<ExistingComment> listIssueComments(String owner, String repo, int prNumber) {
            return List.copyOf(comments);
        }

        @Override
        public void updateComment(String owner, String repo, long commentId, String body) {
            updateCalls.add(new UpdateCall(owner, repo, commentId, body));
            comments.replaceAll(c -> c.id() == commentId ? new ExistingComment(commentId, body) : c);
        }

        @Override
        public void createComment(String owner, String repo, int prNumber, String body) {
            createCalls.add(new CreateCall(owner, repo, prNumber, body));
            comments.add(new ExistingComment(nextId.incrementAndGet(), body));
        }

        record CreateCall(String owner, String repo, int prNumber, String body) {
        }

        record UpdateCall(String owner, String repo, long commentId, String body) {
        }
    }
}
