package dev.reachlayer.core.model;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;

/**
 * The final pipeline output: all findings, sorted by descending {@link Finding#riskScore()},
 * plus enough metadata for an {@code OutputRenderer} to render a "top N that matter" summary.
 */
public record RankedReport(List<Finding> findings, String repo, Instant generatedAt, int topN) {

    public RankedReport {
        findings = findings == null ? List.of() : List.copyOf(findings);
        if (topN < 0) {
            throw new IllegalArgumentException("topN must be >= 0");
        }
    }

    public static RankedReport of(List<Finding> findings, String repo, int topN) {
        List<Finding> sorted = findings.stream()
                .sorted(Comparator.comparingDouble(
                                (Finding f) -> f.riskScore() == null ? 0.0 : f.riskScore())
                        .reversed())
                .toList();
        return new RankedReport(sorted, repo, Instant.now(), topN);
    }

    public List<Finding> top() {
        return findings.size() <= topN ? findings : findings.subList(0, topN);
    }

    public List<Finding> rest() {
        return findings.size() <= topN ? List.of() : findings.subList(topN, findings.size());
    }
}
