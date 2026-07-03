package dev.reachlayer.core.model;

/**
 * A concrete remediation suggestion for a finding. Either LLM-generated ({@code source ==
 * LLM}) or templated ({@code source == TEMPLATE}, the always-available fallback with no API key
 * configured).
 */
public record FixSuggestion(Type type, String text, double confidence, Source source) {

    public enum Type {
        VERSION_BUMP,
        CODE_FIX,
        CONFIG
    }

    public enum Source {
        LLM,
        TEMPLATE
    }

    public FixSuggestion {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("FixSuggestion text must not be blank");
        }
        confidence = Math.max(0.0, Math.min(1.0, confidence));
    }

    public static FixSuggestion template(Type type, String text) {
        return new FixSuggestion(type, text, 0.5, Source.TEMPLATE);
    }

    public static FixSuggestion llm(Type type, String text, double confidence) {
        return new FixSuggestion(type, text, confidence, Source.LLM);
    }
}
