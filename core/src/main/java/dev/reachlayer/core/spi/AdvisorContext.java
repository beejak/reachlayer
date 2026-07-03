package dev.reachlayer.core.spi;

/**
 * Retrieved context assembled for a single finding before asking an {@link LlmProvider} (or the
 * templated fallback) for a fix. Keeping this a plain data holder makes retrieval swappable
 * independent of the provider.
 */
public record AdvisorContext(String advisoryText, String codeSnippet, String dependencyContext) {

    public static AdvisorContext empty() {
        return new AdvisorContext(null, null, null);
    }
}
