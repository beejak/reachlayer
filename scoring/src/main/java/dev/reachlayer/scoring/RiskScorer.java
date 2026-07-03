package dev.reachlayer.scoring;

import dev.reachlayer.core.config.ScoringWeights;
import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.model.RiskExplanation;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Deterministic, explainable risk scorer implementing the blended formula from PLAN.md §8:
 *
 * <pre>
 * base        = normalize(CVSS)              # 0-1
 * exploit     = max(EPSS_percentile, KEV?1.0:0)
 * reachMult   = reachable ? 1.0 : unreachable ? 0.4 : 0.7   (from weights, not hardcoded)
 * blastMult   = 1 + 0.15*internetFacing + 0.1*touchesAuth + 0.1*touchesPII + 0.1*touchesSecrets
 *               (capped at weights.blastRadiusCap())
 * riskScore   = 100 * clamp( (0.5*base + 0.5*exploit) * reachMult * blastMult , 0, 1)
 * </pre>
 *
 * <p>This class is stateless and side-effect free: it never mutates the input {@link Finding}s
 * (they're immutable anyway) and never reorders/drops entries — ranking/sorting is {@code
 * RankedReport}'s job, not this stage's. Every produced score is accompanied by a {@link
 * RiskExplanation} recording each factor's value and provenance so the ordering is auditable.
 */
public final class RiskScorer {

    // Keyword fallback buckets used when a finding has no CVSS and its severity string isn't a
    // parseable number. See the Javadoc on {@link #computeBase(Finding)} for the full chain.
    private static final double SEVERITY_KEYWORD_CRITICAL = 0.9;
    private static final double SEVERITY_KEYWORD_HIGH = 0.7;
    private static final double SEVERITY_KEYWORD_MEDIUM = 0.4;
    private static final double SEVERITY_KEYWORD_LOW = 0.15;
    private static final double SEVERITY_KEYWORD_INFO = 0.05;

    /** Severity string is present but genuinely unrecognized: neutral fallback, not zero. */
    private static final double SEVERITY_UNKNOWN_DEFAULT = 0.5;

    /** Native scale for non-CVSS scanner severities (e.g. Fortify SAST, which scores 0.0-5.0). */
    private static final double NATIVE_SEVERITY_SCALE = 5.0;

    /**
     * Scores every finding in {@code findings} against {@link ScoringWeights#defaults()}. See
     * {@link #score(List, ScoringWeights)}.
     */
    public List<Finding> score(List<Finding> findings) {
        return score(findings, ScoringWeights.defaults());
    }

    /**
     * Computes a blended, explainable {@code riskScore} (0-100) for every finding in {@code
     * findings}, per the formula documented on this class and in PLAN.md §8. Returns a new list
     * of new {@link Finding} instances (via {@link Finding#toBuilder()}) in the same order as the
     * input; the input list and its elements are never mutated.
     *
     * @param findings findings to score; may be empty, never {@code null}
     * @param weights tunable weights/multipliers (see {@link ScoringWeights})
     * @return a new list, same size and order as {@code findings}, each with {@code riskScore}
     *     and {@code riskExplanation} populated
     */
    public List<Finding> score(List<Finding> findings, ScoringWeights weights) {
        List<Finding> result = new ArrayList<>(findings.size());
        for (Finding finding : findings) {
            result.add(scoreOne(finding, weights));
        }
        return result;
    }

    private Finding scoreOne(Finding finding, ScoringWeights weights) {
        BaseResult baseResult = computeBase(finding);
        ExploitResult exploitResult = computeExploit(finding);
        ReachResult reachResult = computeReachMult(finding, weights);
        BlastResult blastResult = computeBlastMult(finding, weights);

        double weightedCore = weights.cvssWeight() * baseResult.value + weights.exploitWeight() * exploitResult.value;
        double combined = weightedCore * reachResult.multiplier * blastResult.multiplier;
        double riskScore = 100.0 * clamp(combined, 0.0, 1.0);

        RiskExplanation explanation = RiskExplanation.builder()
                .add("base", baseResult.value)
                .add("baseSource", baseResult.source)
                .add("exploit", exploitResult.value)
                .add("exploitSource", exploitResult.source)
                .add("reachMult", reachResult.multiplier)
                .add("reachability", reachResult.source)
                .add("blastMult", blastResult.multiplier)
                .add("blastFlags", blastResult.source)
                .add("riskScore", riskScore)
                .build();

        return finding.toBuilder().riskScore(riskScore).riskExplanation(explanation).build();
    }

    /**
     * Computes {@code base} (0-1), the normalized severity signal feeding the risk formula.
     *
     * <p>PLAN.md §8 defines {@code base = normalize(CVSS)} assuming every finding carries a CVSS
     * score. In practice, Fortify SAST findings frequently have no CVSS at all — Fortify scores
     * natively on a 0.0-5.0 scale via {@code Finding.severity()} instead. This method bridges
     * that gap with the following fallback chain, applied in order:
     *
     * <ol>
     *   <li>If {@link Cvss#isKnown()}, use the standard CVSS 0-10 scale: {@code base =
     *       clamp(score / 10.0, 0, 1)}.
     *   <li>Otherwise, try to parse {@link Finding#severity()} as a number and treat it as
     *       Fortify's native 0.0-5.0 scale: {@code base = clamp(value / 5.0, 0, 1)}.
     *   <li>Otherwise, try case-insensitive keyword matching against the severity string:
     *       "critical" → 0.9, "high" → 0.7, "medium"/"moderate" → 0.4, "low" → 0.15,
     *       "info"/"informational" → 0.05.
     *   <li>Otherwise (severity is present but unrecognized, e.g. a scanner-specific label we
     *       don't know), default to {@code base = 0.5} — a documented *neutral* fallback.
     *       Genuinely unknown severity is deliberately not treated as zero risk, since that would
     *       silently bury findings we simply failed to interpret.
     * </ol>
     */
    private BaseResult computeBase(Finding finding) {
        Cvss cvss = finding.cvss();
        if (cvss.isKnown()) {
            double normalized = clamp(cvss.score() / 10.0, 0.0, 1.0);
            return new BaseResult(normalized, "cvss:" + cvss.score());
        }

        String severity = finding.severity();

        try {
            double numeric = Double.parseDouble(severity);
            double normalized = clamp(numeric / NATIVE_SEVERITY_SCALE, 0.0, 1.0);
            return new BaseResult(normalized, "severity-numeric:" + severity);
        } catch (NumberFormatException notNumeric) {
            // fall through to keyword matching
        }

        String normalizedSeverity = severity == null ? "" : severity.toLowerCase(Locale.ROOT);
        if (normalizedSeverity.contains("critical")) {
            return new BaseResult(SEVERITY_KEYWORD_CRITICAL, "severity-keyword:critical");
        }
        if (normalizedSeverity.contains("high")) {
            return new BaseResult(SEVERITY_KEYWORD_HIGH, "severity-keyword:high");
        }
        if (normalizedSeverity.contains("medium") || normalizedSeverity.contains("moderate")) {
            return new BaseResult(SEVERITY_KEYWORD_MEDIUM, "severity-keyword:medium");
        }
        if (normalizedSeverity.contains("low")) {
            return new BaseResult(SEVERITY_KEYWORD_LOW, "severity-keyword:low");
        }
        if (normalizedSeverity.contains("info")) {
            return new BaseResult(SEVERITY_KEYWORD_INFO, "severity-keyword:info");
        }

        return new BaseResult(SEVERITY_UNKNOWN_DEFAULT, "unknown-default:" + severity);
    }

    /**
     * Computes {@code exploit = max(EPSS_percentile, KEV ? 1.0 : 0)}. KEV membership pins the
     * value to 1.0 regardless of EPSS, per PLAN.md §8 ("KEV membership pins high").
     */
    private ExploitResult computeExploit(Finding finding) {
        Epss epss = finding.epss();
        double epssPercentile = epss == null ? 0.0 : epss.percentile();
        double kevValue = finding.kev() ? 1.0 : 0.0;
        double exploit = Math.max(epssPercentile, kevValue);

        String source = finding.kev()
                ? "kev-pinned (epssPercentile=" + epssPercentile + ")"
                : "epssPercentile=" + epssPercentile;
        return new ExploitResult(exploit, source);
    }

    /** Computes {@code reachMult} from {@link Finding#reachability()} and configured weights. */
    private ReachResult computeReachMult(Finding finding, ScoringWeights weights) {
        Reachability reachability = finding.reachability();
        double multiplier =
                switch (reachability) {
                    case REACHABLE -> weights.reachableMultiplier();
                    case UNREACHABLE -> weights.unreachableMultiplier();
                    case UNKNOWN -> weights.unknownMultiplier();
                };
        return new ReachResult(multiplier, reachability.wireValue());
    }

    /**
     * Computes {@code blastMult}, capped at {@link ScoringWeights#blastRadiusCap()}.
     */
    private BlastResult computeBlastMult(Finding finding, ScoringWeights weights) {
        BlastRadius blastRadius = finding.blastRadius();
        double uncapped = 1.0
                + (blastRadius.internetFacing() ? weights.internetFacingWeight() : 0.0)
                + (blastRadius.touchesAuth() ? weights.touchesAuthWeight() : 0.0)
                + (blastRadius.touchesPii() ? weights.touchesPiiWeight() : 0.0)
                + (blastRadius.touchesSecrets() ? weights.touchesSecretsWeight() : 0.0);
        double capped = Math.min(weights.blastRadiusCap(), uncapped);

        String flags = blastRadius.summary();
        String source = (flags.isEmpty() ? "none" : flags) + " (uncapped=" + uncapped + ")";
        return new BlastResult(capped, source);
    }

    private static double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    private record BaseResult(double value, String source) {
    }

    private record ExploitResult(double value, String source) {
    }

    private record ReachResult(double multiplier, String source) {
    }

    private record BlastResult(double multiplier, String source) {
    }
}
