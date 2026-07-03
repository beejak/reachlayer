package dev.reachlayer.core.config;

/**
 * Tunable weights for the deterministic risk formula in PLAN.md §8:
 *
 * <pre>
 * base        = normalize(CVSS)
 * exploit     = max(EPSS_percentile, KEV ? 1.0 : 0)
 * reachMult   = reachable ? reachableMultiplier
 *               : unreachable ? unreachableMultiplier
 *               : unknownMultiplier
 * blastMult   = min(blastRadiusCap, 1 + internetFacingWeight*internetFacing
 *               + touchesAuthWeight*touchesAuth + touchesPiiWeight*touchesPii
 *               + touchesSecretsWeight*touchesSecrets)
 * riskScore   = 100 * clamp((cvssWeight*base + exploitWeight*exploit) * reachMult * blastMult, 0, 1)
 * </pre>
 *
 * Defaults match the starting point in PLAN.md §8 exactly; every field is overridable via
 * {@code reachlayer.yml}.
 */
public record ScoringWeights(
        double cvssWeight,
        double exploitWeight,
        double reachableMultiplier,
        double unreachableMultiplier,
        double unknownMultiplier,
        double internetFacingWeight,
        double touchesAuthWeight,
        double touchesPiiWeight,
        double touchesSecretsWeight,
        double blastRadiusCap) {

    public static ScoringWeights defaults() {
        return new ScoringWeights(0.5, 0.5, 1.0, 0.4, 0.7, 0.15, 0.1, 0.1, 0.1, 1.5);
    }
}
