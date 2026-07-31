package dev.reachlayer.core.baseline;

import dev.reachlayer.core.model.Finding;
import java.util.List;
import java.util.Set;

/**
 * Pure tagging logic for "baseline/diff mode" (PLAN.md §5 Phase 1): marks each {@link Finding}'s
 * {@link Finding#isNew()} relative to a set of baseline finding ids. No I/O — {@link
 * BaselineStore} owns reading the baseline file; this class only ever sees the already-loaded
 * {@code Set<String>} (or {@code null}, meaning "no baseline in play").
 */
public final class BaselineDiffer {

    private BaselineDiffer() {
    }

    /**
     * Returns {@code findings} with each element's {@link Finding#isNew()} set to {@code
     * !baselineIds.contains(finding.id())} — {@code true} for a finding introduced since the
     * baseline was captured, {@code false} for one already present in it.
     *
     * <p>If {@code baselineIds} is {@code null} (no baseline was read), {@code findings} is
     * returned unchanged: every finding's {@code isNew()} stays whatever it already was (normally
     * {@code null}), exactly today's pre-baseline-mode behavior.
     */
    public static List<Finding> tag(List<Finding> findings, Set<String> baselineIds) {
        if (baselineIds == null) {
            return findings;
        }
        return findings.stream()
                .map(f -> f.toBuilder().isNew(!baselineIds.contains(f.id())).build())
                .toList();
    }
}
