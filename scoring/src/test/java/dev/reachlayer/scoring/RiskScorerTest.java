package dev.reachlayer.scoring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import dev.reachlayer.core.config.ScoringWeights;
import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Reachability;
import java.util.List;
import org.junit.jupiter.api.Test;

class RiskScorerTest {

    private static final double EPS = 0.01;

    private final RiskScorer scorer = new RiskScorer();

    /** Minimal valid finding, override fields per-test via {@link Finding.Builder}. */
    private static Finding.Builder baseFinding() {
        return Finding.builder()
                .id("f-1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .cvss(Cvss.UNKNOWN)
                .severity("unknown")
                .reachability(Reachability.UNKNOWN)
                .kev(false)
                .blastRadius(BlastRadius.NONE);
    }

    @Test
    void knownCvssScoreProducesCorrectBase() {
        Finding finding = baseFinding().cvss(new Cvss(7.5, "AV:N/AC:L")).build();

        Finding scored = scorer.score(List.of(finding), ScoringWeights.defaults()).get(0);

        // base = 7.5 / 10.0 = 0.75; exploit = 0 (no epss, no kev); reachMult = 0.7 (unknown);
        // blastMult = 1.0 (no flags)
        // riskScore = 100 * clamp((0.5*0.75 + 0.5*0) * 0.7 * 1.0, 0, 1) = 100 * 0.375*0.7 = 26.25
        assertThat(scored.riskScore()).isCloseTo(26.25, within(EPS));
        assertThat(scored.riskExplanation().render()).contains("cvss:7.5");
    }

    @Test
    void unknownCvssNumericFortifySeverityUsesFiveScaleFallback() {
        Finding finding = baseFinding().cvss(Cvss.UNKNOWN).severity("4.0").build();

        Finding scored = scorer.score(List.of(finding)).get(0);

        // base = 4.0 / 5.0 = 0.8
        // exploit = 0; reachMult = 0.7 (unknown); blastMult = 1.0
        // riskScore = 100 * (0.5*0.8) * 0.7 = 28.0
        assertThat(scored.riskScore()).isCloseTo(28.0, within(EPS));
        assertThat(scored.riskExplanation().render()).contains("severity-numeric:4.0");
    }

    @Test
    void unknownCvssTextualSeverityUsesKeywordFallbackCaseInsensitive() {
        Finding finding = baseFinding().cvss(Cvss.UNKNOWN).severity("High").build();

        Finding scored = scorer.score(List.of(finding)).get(0);

        // base = 0.7 (high keyword); exploit = 0; reachMult = 0.7; blastMult = 1.0
        // riskScore = 100 * (0.5*0.7) * 0.7 = 24.5
        assertThat(scored.riskScore()).isCloseTo(24.5, within(EPS));
        assertThat(scored.riskExplanation().render()).contains("severity-keyword:high");
    }

    @Test
    void unrecognizedSeverityDefaultsToNeutralPointFive() {
        Finding finding = baseFinding().cvss(Cvss.UNKNOWN).severity("banana").build();

        Finding scored = scorer.score(List.of(finding)).get(0);

        // base = 0.5 default; exploit = 0; reachMult = 0.7; blastMult = 1.0
        // riskScore = 100 * (0.5*0.5) * 0.7 = 17.5
        assertThat(scored.riskScore()).isCloseTo(17.5, within(EPS));
        assertThat(scored.riskExplanation().render()).contains("unknown-default:banana");
    }

    @Test
    void kevPinsExploitToOneEvenWithLowOrNoEpss() {
        Finding withNoEpss = baseFinding().kev(true).epss(null).build();
        Finding withLowEpss = baseFinding().kev(true).epss(new Epss(0.01, 0.02, "2026-06-30")).build();

        Finding scoredNoEpss = scorer.score(List.of(withNoEpss)).get(0);
        Finding scoredLowEpss = scorer.score(List.of(withLowEpss)).get(0);

        assertThat(scoredNoEpss.riskExplanation().render()).contains("exploit: 1.0");
        assertThat(scoredLowEpss.riskExplanation().render()).contains("exploit: 1.0");
    }

    @Test
    void epssPercentileUsedWhenKevFalse() {
        Finding finding = baseFinding().kev(false).epss(new Epss(0.3, 0.65, "2026-06-30")).build();

        Finding scored = scorer.score(List.of(finding)).get(0);

        assertThat(scored.riskExplanation().render()).contains("exploit: 0.65");
    }

    @Test
    void reachableMultiplierAppliedFromCustomWeights() {
        ScoringWeights customWeights = new ScoringWeights(
                /* cvssWeight */ 0.5,
                /* exploitWeight */ 0.5,
                /* reachableMultiplier */ 0.9,
                /* unreachableMultiplier */ 0.3,
                /* unknownMultiplier */ 0.6,
                /* internetFacingWeight */ 0.15,
                /* touchesAuthWeight */ 0.1,
                /* touchesPiiWeight */ 0.1,
                /* touchesSecretsWeight */ 0.1,
                /* blastRadiusCap */ 1.5);
        Finding finding = baseFinding().cvss(new Cvss(10.0, null)).reachability(Reachability.REACHABLE).build();

        Finding scored = scorer.score(List.of(finding), customWeights).get(0);

        // base = 1.0; exploit = 0; reachMult = 0.9 (custom reachable); blastMult = 1.0
        // riskScore = 100 * (0.5*1.0) * 0.9 * 1.0 = 45.0
        assertThat(scored.riskScore()).isCloseTo(45.0, within(EPS));
    }

    @Test
    void unreachableMultiplierAppliedFromCustomWeights() {
        ScoringWeights customWeights = new ScoringWeights(0.5, 0.5, 0.9, 0.3, 0.6, 0.15, 0.1, 0.1, 0.1, 1.5);
        Finding finding = baseFinding().cvss(new Cvss(10.0, null)).reachability(Reachability.UNREACHABLE).build();

        Finding scored = scorer.score(List.of(finding), customWeights).get(0);

        // base = 1.0; exploit = 0; reachMult = 0.3 (custom unreachable); blastMult = 1.0
        // riskScore = 100 * 0.5 * 0.3 = 15.0
        assertThat(scored.riskScore()).isCloseTo(15.0, within(EPS));
    }

    @Test
    void unknownMultiplierAppliedFromCustomWeights() {
        ScoringWeights customWeights = new ScoringWeights(0.5, 0.5, 0.9, 0.3, 0.6, 0.15, 0.1, 0.1, 0.1, 1.5);
        Finding finding = baseFinding().cvss(new Cvss(10.0, null)).reachability(Reachability.UNKNOWN).build();

        Finding scored = scorer.score(List.of(finding), customWeights).get(0);

        // base = 1.0; exploit = 0; reachMult = 0.6 (custom unknown); blastMult = 1.0
        // riskScore = 100 * 0.5 * 0.6 = 30.0
        assertThat(scored.riskScore()).isCloseTo(30.0, within(EPS));
    }

    @Test
    void blastRadiusMultiplierIsCappedWithCustomWeights() {
        // Custom weights where all four flags would sum to 1 + 0.5*4 = 3.0, well above a 1.4 cap.
        ScoringWeights customWeights = new ScoringWeights(
                0.5, 0.5, 1.0, 0.4, 0.7,
                /* internetFacingWeight */ 0.5,
                /* touchesAuthWeight */ 0.5,
                /* touchesPiiWeight */ 0.5,
                /* touchesSecretsWeight */ 0.5,
                /* blastRadiusCap */ 1.4);
        BlastRadius allFlags = new BlastRadius(true, true, true, true, List.of());
        Finding finding = baseFinding()
                .cvss(new Cvss(10.0, null))
                .reachability(Reachability.REACHABLE)
                .blastRadius(allFlags)
                .build();

        Finding scored = scorer.score(List.of(finding), customWeights).get(0);

        // base = 1.0; exploit = 0; reachMult = 1.0; blastMult = min(1.4, 3.0) = 1.4
        // riskScore = 100 * clamp(0.5 * 1.0 * 1.4, 0, 1) = 70.0
        assertThat(scored.riskScore()).isCloseTo(70.0, within(EPS));
        assertThat(scored.riskExplanation().render()).contains("blastMult: 1.4");
    }

    @Test
    void riskExplanationIsNonNullAndRendersRecognizableFactors() {
        Finding finding = baseFinding()
                .cvss(new Cvss(6.0, null))
                .kev(true)
                .reachability(Reachability.REACHABLE)
                .blastRadius(new BlastRadius(true, false, true, false, List.of()))
                .build();

        Finding scored = scorer.score(List.of(finding)).get(0);

        assertThat(scored.riskExplanation()).isNotNull();
        String rendered = scored.riskExplanation().render();
        assertThat(rendered)
                .contains("base:")
                .contains("baseSource:")
                .contains("exploit:")
                .contains("exploitSource:")
                .contains("reachMult:")
                .contains("reachability:")
                .contains("blastMult:")
                .contains("blastFlags:")
                .contains("riskScore:");
    }

    @Test
    void endToEndHandComputedExample() {
        // CVSS 8.0 -> base = 0.8
        // EPSS percentile 0.4, not KEV -> exploit = 0.4
        // Reachable -> reachMult = 1.0 (default weights)
        // internetFacing + touchesSecrets -> blastMult = 1 + 0.15 + 0.1 = 1.25 (default weights, uncapped since < 1.5)
        // riskScore = 100 * clamp((0.5*0.8 + 0.5*0.4) * 1.0 * 1.25, 0, 1)
        //           = 100 * clamp(0.6 * 1.25, 0, 1) = 100 * 0.75 = 75.0
        Finding finding = baseFinding()
                .cvss(new Cvss(8.0, "AV:N/AC:L/PR:N"))
                .epss(new Epss(0.35, 0.4, "2026-06-30"))
                .kev(false)
                .reachability(Reachability.REACHABLE)
                .blastRadius(new BlastRadius(true, false, false, true, List.of()))
                .build();

        Finding scored = scorer.score(List.of(finding), ScoringWeights.defaults()).get(0);

        assertThat(scored.riskScore()).isCloseTo(75.0, within(EPS));
    }

    @Test
    void doesNotMutateInputOrReorderList() {
        Finding a = baseFinding().id("a").cvss(new Cvss(3.0, null)).build();
        Finding b = baseFinding().id("b").cvss(new Cvss(9.0, null)).build();
        List<Finding> input = List.of(a, b);

        List<Finding> scored = scorer.score(input, ScoringWeights.defaults());

        // originals untouched
        assertThat(a.riskScore()).isNull();
        assertThat(b.riskScore()).isNull();
        // order preserved
        assertThat(scored).hasSize(2);
        assertThat(scored.get(0).id()).isEqualTo("a");
        assertThat(scored.get(1).id()).isEqualTo("b");
        assertThat(scored.get(0).riskScore()).isNotNull();
        assertThat(scored.get(1).riskScore()).isNotNull();
    }
}
