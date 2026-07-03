package dev.reachlayer.core.model;

/** Scanner-reported CVSS score/vector, kept as-is and never overridden by Reachlayer. */
public record Cvss(Double score, String vector) {

    public static final Cvss UNKNOWN = new Cvss(null, null);

    public boolean isKnown() {
        return score != null;
    }
}
