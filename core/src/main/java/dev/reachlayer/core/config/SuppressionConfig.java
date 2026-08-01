package dev.reachlayer.core.config;

import java.util.Map;

/**
 * User-configured **display**-suppression rules (PLAN.md §5 Phase 1, "suppression-of-*display*
 * rules (never suppression of data)"). This is deliberately narrow: it only ever affects what
 * {@code MarkdownReportFormatter} puts in its rendered table. It never removes a finding from
 * {@link dev.reachlayer.core.model.RankedReport}, never affects the SARIF renderer, the baseline
 * store, or pipeline metrics — every one of those still sees and counts every finding Fortify or
 * Black Duck reported, exactly as PLAN.md §2 principle 3 ("never suppress a finding") requires.
 *
 * @param displayCwes CWE id (e.g. {@code "CWE-563"}) to a required, non-blank human-readable
 *     reason a team chose to hide that CWE from the primary display — required, not optional, so
 *     a suppression rule is always self-documenting and auditable rather than a silent policy no
 *     one remembers the justification for.
 */
public record SuppressionConfig(Map<String, String> displayCwes) {

    public SuppressionConfig {
        displayCwes = displayCwes == null ? Map.of() : Map.copyOf(displayCwes);
    }

    public static SuppressionConfig defaults() {
        return new SuppressionConfig(Map.of());
    }
}
