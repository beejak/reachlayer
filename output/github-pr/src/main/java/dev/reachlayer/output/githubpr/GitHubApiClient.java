package dev.reachlayer.output.githubpr;

import java.io.IOException;
import java.util.List;

/**
 * The narrow slice of the GitHub REST API needed to upsert a single marker-tagged issue comment
 * on a pull request. Kept minimal and mockable on purpose — this is not a general GitHub SDK.
 */
public interface GitHubApiClient {

    /** Lists all issue comments on the given PR (GitHub PRs are backed by an "issue" of the same number). */
    List<ExistingComment> listIssueComments(String owner, String repo, int prNumber) throws IOException;

    /** Replaces the body of an existing comment. */
    void updateComment(String owner, String repo, long commentId, String body) throws IOException;

    /** Creates a new comment on the given PR. */
    void createComment(String owner, String repo, int prNumber, String body) throws IOException;

    /** A previously-posted issue comment, as returned by {@link #listIssueComments}. */
    record ExistingComment(long id, String body) {
    }
}
