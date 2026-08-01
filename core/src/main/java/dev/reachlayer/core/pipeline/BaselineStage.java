package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/**
 * Baseline/diff tagging stage (PLAN.md §5 Phase 1, "baseline/diff mode"): tags each finding's
 * {@link Finding#isNew()} relative to a prior run's baseline. Mirrors {@link ReachabilityStage}/
 * {@link EnrichmentStage}/{@link ScoringStage}/{@link AdvisorStage} for consistency with the
 * other pipeline stages.
 */
@FunctionalInterface
public interface BaselineStage {
    List<Finding> tag(List<Finding> findings);
}
