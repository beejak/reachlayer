package dev.reachlayer.core.spi;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FixSuggestion;

/**
 * Pluggable fix-advisor backend. The default {@code noop} provider is a fully-functional
 * templated fallback requiring no API key; an {@code anthropic} (or other) provider can be
 * configured to generate higher-quality, context-aware suggestions. Providers should be called
 * only for top-ranked findings (see PLAN.md §9 risk 5) — that policy lives in the advisor
 * module, not here.
 */
public interface LlmProvider {

    /** Short identifier, e.g. {@code "noop"} or {@code "anthropic"}. */
    String name();

    /** True if this provider is usable in the current environment (e.g. an API key is set). */
    boolean isAvailable();

    /** Produces a fix suggestion for the given finding using the retrieved context. */
    FixSuggestion suggest(Finding finding, AdvisorContext context);
}
