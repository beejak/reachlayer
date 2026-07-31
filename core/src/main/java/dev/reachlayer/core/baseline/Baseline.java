package dev.reachlayer.core.baseline;

import java.time.Instant;
import java.util.Set;

/**
 * An in-memory baseline: the set of {@link dev.reachlayer.core.model.Finding#id()} values observed
 * by a prior run (typically a scheduled scan of the base branch), plus the instant it was
 * captured. Round-trips to/from disk via {@link BaselineStore}. See PLAN.md §5 Phase 1,
 * "baseline/diff mode."
 */
public record Baseline(Instant generatedAt, Set<String> findingIds) {

    public Baseline {
        findingIds = findingIds == null ? Set.of() : Set.copyOf(findingIds);
    }
}
