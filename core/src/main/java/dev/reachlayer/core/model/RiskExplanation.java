package dev.reachlayer.core.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-factor breakdown of how a {@link Finding#riskScore()} was computed, so developers can
 * trust (and audit) the ordering. Preserves insertion order for stable rendering.
 */
public record RiskExplanation(Map<String, String> factors) {

    public RiskExplanation {
        factors = factors == null ? Map.of() : new LinkedHashMap<>(factors);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, String> factors = new LinkedHashMap<>();

        public Builder add(String factor, String explanation) {
            factors.put(factor, explanation);
            return this;
        }

        public Builder add(String factor, double value) {
            return add(factor, String.valueOf(value));
        }

        public RiskExplanation build() {
            return new RiskExplanation(factors);
        }
    }

    /** Renders as {@code "factor: value; factor2: value2"}. */
    public String render() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : factors.entrySet()) {
            if (!sb.isEmpty()) {
                sb.append("; ");
            }
            sb.append(e.getKey()).append(": ").append(e.getValue());
        }
        return sb.toString();
    }
}
