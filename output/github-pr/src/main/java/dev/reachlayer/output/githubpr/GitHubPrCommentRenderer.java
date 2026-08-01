package dev.reachlayer.output.githubpr;

import dev.reachlayer.core.config.OutputConfig;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.output.api.MarkdownReportFormatter;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * The MVP output surface (PLAN.md §3.1/§7): upserts a single marker-tagged PR comment rather than
 * posting a new comment on every push. The marker is an HTML comment embedded at the top of the
 * rendered Markdown; {@link #render} looks for an existing comment containing that marker and
 * updates it in place, only creating a new comment if none is found.
 */
public final class GitHubPrCommentRenderer implements OutputRenderer {

    private final GitHubApiClient client;
    private final String owner;
    private final String repo;
    private final int prNumber;
    private final String commentMarker;
    private final MarkdownReportFormatter formatter;

    public GitHubPrCommentRenderer(
            GitHubApiClient client,
            String owner,
            String repo,
            int prNumber,
            String commentMarker,
            MarkdownReportFormatter formatter) {
        this.client = Objects.requireNonNull(client, "client");
        this.owner = Objects.requireNonNull(owner, "owner");
        this.repo = Objects.requireNonNull(repo, "repo");
        this.prNumber = prNumber;
        this.commentMarker = Objects.requireNonNull(commentMarker, "commentMarker");
        this.formatter = formatter == null ? new MarkdownReportFormatter() : formatter;
    }

    /** Convenience constructor using the default {@link MarkdownReportFormatter}. */
    public GitHubPrCommentRenderer(
            GitHubApiClient client, String owner, String repo, int prNumber, String commentMarker) {
        this(client, owner, repo, prNumber, commentMarker, new MarkdownReportFormatter());
    }

    /**
     * Builds a renderer from CI environment variables: {@code GITHUB_REPOSITORY} (format
     * {@code "owner/repo"}) and {@code GITHUB_PR_NUMBER}. The comment marker defaults to {@link
     * OutputConfig#defaults()}'s marker. The {@link GitHubApiClient} is injected by the caller so
     * this stays testable.
     *
     * @throws IllegalStateException if the required environment variables are missing or
     *     unparseable
     */
    public static GitHubPrCommentRenderer fromEnvironment(GitHubApiClient client) {
        return fromEnvironment(client, new MarkdownReportFormatter());
    }

    /** As {@link #fromEnvironment(GitHubApiClient)}, using a caller-supplied {@code formatter}
     * (e.g. one configured with {@code reachlayer.yml}'s suppression rules) instead of the
     * default. */
    public static GitHubPrCommentRenderer fromEnvironment(GitHubApiClient client, MarkdownReportFormatter formatter) {
        String[] ownerRepo = parseOwnerRepo(System.getenv("GITHUB_REPOSITORY"));
        int prNumber = parsePrNumber(System.getenv("GITHUB_PR_NUMBER"));
        return new GitHubPrCommentRenderer(
                client, ownerRepo[0], ownerRepo[1], prNumber, OutputConfig.defaults().commentMarker(), formatter);
    }

    /**
     * Parses {@code "owner/repo"} into a two-element array {@code [owner, repo]}.
     *
     * <p>Package-private (rather than private) so it can be exercised directly by tests with fake
     * string inputs instead of relying on real environment variables.
     */
    static String[] parseOwnerRepo(String githubRepository) {
        if (githubRepository == null || githubRepository.isBlank()) {
            throw new IllegalStateException("GITHUB_REPOSITORY environment variable is required (format \"owner/repo\")");
        }
        String[] parts = githubRepository.split("/", 2);
        if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
            throw new IllegalStateException(
                    "GITHUB_REPOSITORY must be in \"owner/repo\" format, got: " + githubRepository);
        }
        return parts;
    }

    /** Package-private for direct testing; see {@link #parseOwnerRepo(String)}. */
    static int parsePrNumber(String githubPrNumber) {
        if (githubPrNumber == null || githubPrNumber.isBlank()) {
            throw new IllegalStateException("GITHUB_PR_NUMBER environment variable is required");
        }
        try {
            return Integer.parseInt(githubPrNumber.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("GITHUB_PR_NUMBER must be an integer, got: " + githubPrNumber, e);
        }
    }

    @Override
    public String name() {
        return "github-pr";
    }

    @Override
    public void render(RankedReport report) throws OutputException {
        String markdown = formatter.format(report, commentMarker);

        try {
            List<GitHubApiClient.ExistingComment> existingComments = client.listIssueComments(owner, repo, prNumber);
            GitHubApiClient.ExistingComment target = existingComments.stream()
                    .filter(c -> c.body() != null && c.body().contains(commentMarker))
                    .findFirst()
                    .orElse(null);

            if (target != null) {
                client.updateComment(owner, repo, target.id(), markdown);
            } else {
                client.createComment(owner, repo, prNumber, markdown);
            }
        } catch (IOException e) {
            throw new OutputException(
                    "Failed to upsert Reachlayer PR comment on " + owner + "/" + repo + "#" + prNumber + ": "
                            + e.getMessage(),
                    e);
        }
    }
}
