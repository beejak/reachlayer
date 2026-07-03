package dev.reachlayer.core.model;

/**
 * EPSS (Exploit Prediction Scoring System) score for a CVE, as of {@code asOf}. A {@code null}
 * reference on {@link Finding} means "no EPSS data available", not zero risk.
 */
public record Epss(double score, double percentile, String asOf) {
}
