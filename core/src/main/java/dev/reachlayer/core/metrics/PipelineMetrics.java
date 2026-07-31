package dev.reachlayer.core.metrics;

import java.time.Instant;
import java.util.Map;

/**
 * Operational metrics for a single {@code Orchestrator.run(...)} invocation: per-stage timing and
 * failures, finding counts by severity/source/reachability, and output-renderer success/failure
 * counts. Populated by {@code core.pipeline.Orchestrator} and exposed via its {@code metrics()}
 * getter after a run completes; written to disk (optionally) via {@link MetricsWriter}.
 *
 * <p>This is observability, not a report — nobody's PR comment shows this; it exists so a CI
 * operator can see how long each stage took and which ones degraded, without re-deriving it from
 * log scraping.
 */
public record PipelineMetrics(
        Instant startedAt,
        Instant completedAt,
        long totalDurationMs,
        int sourcesRequested,
        int findingsIngested,
        Map<String, Long> stageDurationMs,
        Map<String, String> stageErrors,
        Map<String, Integer> findingCountsBySeverity,
        Map<String, Integer> findingCountsBySource,
        Map<String, Integer> findingCountsByReachability,
        int outputRenderersSucceeded,
        int outputRenderersFailed,
        Map<String, String> outputRendererErrors) {

    public PipelineMetrics {
        stageDurationMs = stageDurationMs == null ? Map.of() : Map.copyOf(stageDurationMs);
        stageErrors = stageErrors == null ? Map.of() : Map.copyOf(stageErrors);
        findingCountsBySeverity = findingCountsBySeverity == null ? Map.of() : Map.copyOf(findingCountsBySeverity);
        findingCountsBySource = findingCountsBySource == null ? Map.of() : Map.copyOf(findingCountsBySource);
        findingCountsByReachability =
                findingCountsByReachability == null ? Map.of() : Map.copyOf(findingCountsByReachability);
        outputRendererErrors = outputRendererErrors == null ? Map.of() : Map.copyOf(outputRendererErrors);
    }
}
