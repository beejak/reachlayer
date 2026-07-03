package dev.reachlayer.advisor.api;

import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.core.config.AdvisorConfig;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.spi.AdvisorContext;
import dev.reachlayer.core.spi.LlmProvider;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Top-level fix-advisor orchestrator (PLAN.md §3.1, §7). Wraps a pluggable {@link LlmProvider}
 * and applies the "never call the LLM for every finding" policy from PLAN.md §9 risk 5: only the
 * first {@code config.topNForLlm()} findings — assumed already ranked by the scoring stage that
 * runs earlier in the pipeline, most important first — get a real LLM call. Everything else, plus
 * anything the provider fails to handle, falls back to a deterministic templated suggestion so
 * the stage can never fail the build (PLAN.md §1).
 *
 * <p>Implements {@link AdvisorStage} directly so it can be wired into the pipeline as-is, or
 * referenced via {@code service::advise} where a bare {@code AdvisorStage} is expected.
 */
public final class FixAdvisorService implements AdvisorStage {

    private static final Logger log = LoggerFactory.getLogger(FixAdvisorService.class);

    private final LlmProvider provider;
    private final AdvisorConfig config;
    private final ContextBuilder contextBuilder;
    private final Path repoRoot;

    /**
     * @param provider the LLM backend to use for top-ranked findings, or {@code null} to use the
     *     templated fallback for every finding (e.g. no provider configured/available)
     * @param config advisor configuration; only {@code topNForLlm()} is consulted here — which
     *     provider to construct is the caller's responsibility when wiring {@code provider}
     * @param contextBuilder assembles the {@link AdvisorContext} passed to the provider; if
     *     {@code null} a default {@link ContextBuilder} is used
     * @param repoRoot repository root used for code-snippet retrieval, or {@code null} if unknown
     *     (context is still built, just without a snippet — see {@link ContextBuilder})
     */
    public FixAdvisorService(LlmProvider provider, AdvisorConfig config, ContextBuilder contextBuilder, Path repoRoot) {
        this.provider = provider;
        this.config = config == null ? AdvisorConfig.defaults() : config;
        this.contextBuilder = contextBuilder == null ? new ContextBuilder() : contextBuilder;
        this.repoRoot = repoRoot;
    }

    @Override
    public List<Finding> advise(List<Finding> findings) {
        boolean providerUsable = provider != null && provider.isAvailable();
        int topN = Math.max(0, config.topNForLlm());

        List<Finding> result = new ArrayList<>(findings.size());
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            FixSuggestion suggestion =
                    (providerUsable && i < topN) ? suggestViaProvider(finding) : templatedFallback(finding);
            result.add(finding.toBuilder().fixSuggestion(suggestion).build());
        }
        return result;
    }

    private FixSuggestion suggestViaProvider(Finding finding) {
        try {
            AdvisorContext context = contextBuilder.buildContext(finding, repoRoot);
            FixSuggestion suggestion = provider.suggest(finding, context);
            if (suggestion == null) {
                throw new IllegalStateException("provider '" + provider.name() + "' returned a null suggestion");
            }
            return suggestion;
        } catch (RuntimeException e) {
            // A single provider hiccup (network failure, malformed response, rate limit, ...)
            // must never break the whole batch — degrade to the templated suggestion for just
            // this finding and keep going. See PLAN.md §1 "never fail or block the build".
            log.warn(
                    "LLM provider '{}' failed to produce a fix for finding {}; falling back to a templated"
                            + " suggestion: {}",
                    provider.name(),
                    finding.id(),
                    e.toString());
            return templatedFallback(finding);
        }
    }

    // --- internal templated fallback ---
    //
    // advisor:providers:noop implements the "real", standalone version of this same idea as a
    // registrable LlmProvider. We deliberately duplicate a small amount of templating logic here
    // instead of depending on advisor:providers:noop from advisor:api: providers depend on api
    // (and core), never the reverse, so api pulling in a sibling provider module would invert
    // the intended module dependency direction (and risk a cycle once other providers exist).
    // The duplication is small, self-contained, and easy to keep in sync if the format changes.

    private FixSuggestion templatedFallback(Finding finding) {
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
