package dev.reachlayer.core.config;

/**
 * Fix-advisor configuration: which {@code LlmProvider} to use and how many top-ranked findings
 * to spend LLM calls on (PLAN.md §9 risk 5 — never call the LLM for every finding).
 */
public record AdvisorConfig(String provider, int topNForLlm) {

    public static AdvisorConfig defaults() {
        return new AdvisorConfig("noop", 5);
    }
}
