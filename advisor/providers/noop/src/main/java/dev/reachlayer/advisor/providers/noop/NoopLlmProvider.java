package dev.reachlayer.advisor.providers.noop;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.spi.AdvisorContext;
import dev.reachlayer.core.spi.LlmProvider;

/**
 * The always-available templated fallback provider (PLAN.md §3.1/§4/§7): "a deterministic
 * templated fallback so the tool is fully functional with no LLM key". This is the default {@code
 * LlmProvider} registered when no real provider is configured, or when {@code
 * AdvisorConfig.provider()} is explicitly set to {@code "noop"}.
 *
 * <p>{@code advisor:api}'s {@code FixAdvisorService} contains a small internal fallback of its
 * own for the case where {@code provider == null} or a real provider throws — this class is the
 * standalone, directly-usable form of that same templating idea, registrable like any other
 * {@link LlmProvider}. Some duplication between the two is expected and documented in both
 * places.
 */
public final class NoopLlmProvider implements LlmProvider {

    @Override
    public String name() {
        return "noop";
    }

    /** Always {@code true} — this provider requires no API key or network access. */
    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public FixSuggestion suggest(Finding finding, AdvisorContext context) {
        Component component = finding.component();
        if (finding.kind() == FindingKind.SCA && component != null) {
            String cveList = finding.cve().isEmpty() ? "no known CVE ids" : String.join(", ", finding.cve());
            String description = isBlank(finding.description())
                    ? "No further detail was provided by the scanner."
                    : finding.description();
            String text = "Upgrade " + component.coordinate() + " to a patched release addressing " + cveList + ". "
                    + description;
            return FixSuggestion.template(FixSuggestion.Type.VERSION_BUMP, text);
        }
        if (finding.kind() == FindingKind.SAST) {
            String title = isBlank(finding.title()) ? "this finding" : finding.title();
            String description = isBlank(finding.description()) ? "" : " " + finding.description();
            String text = "Review '" + title + "' at " + finding.location() + "." + description
                    + " Validate and sanitize untrusted input before use; prefer parameterized queries / safe"
                    + " framework APIs appropriate to this finding type.";
            return FixSuggestion.template(FixSuggestion.Type.CODE_FIX, text);
        }
        String title = isBlank(finding.title()) ? "this finding" : finding.title();
        return FixSuggestion.template(
                FixSuggestion.Type.CONFIG,
                "Manual review recommended for '" + title + "'; no automated remediation template applies.");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
