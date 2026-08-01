package dev.reachlayer.evals;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.evals.fixtures.RankingScenario;
import dev.reachlayer.scoring.RiskScorer;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Ablation-style eval: proves Reachlayer's blended risk score (CVSS + EPSS/KEV + reachability +
 * blast-radius, PLAN.md §8) actually beats naive CVSS-only sorting on {@link RankingScenario},
 * rather than merely asserting the scorer runs without throwing (that correctness check belongs
 * to {@code scoring}'s own unit tests). This is the "does the added complexity earn its keep"
 * check.
 */
class RiskRankingEvalTest {

    @Test
    void reachlayerRankingBeatsCvssOnlyBaselineOnPrecisionAtThree() {
        List<Finding> findings = RankingScenario.findings();
        Set<String> groundTruthTop3 = RankingScenario.groundTruthTop3Ids();

        List<String> baselineRanking = findings.stream()
                .sorted(Comparator.comparingDouble(Metrics::cvssOrZero).reversed())
                .map(Finding::id)
                .toList();

        List<Finding> scored = new RiskScorer().score(findings);
        List<String> reachlayerRanking = scored.stream()
                .sorted(Comparator.comparingDouble((Finding f) -> f.riskScore() == null ? 0.0 : f.riskScore())
                        .reversed())
                .map(Finding::id)
                .toList();

        double baselinePrecision = Metrics.precisionAtK(baselineRanking, groundTruthTop3, 3);
        double reachlayerPrecision = Metrics.precisionAtK(reachlayerRanking, groundTruthTop3, 3);

        assertThat(reachlayerPrecision)
                .as(
                        "Reachlayer's blended risk score (baseline precision@3=%.2f, ranking=%s) should rank the "
                                + "ground-truth top-3 findings above naive CVSS-only sorting (ranking=%s) on this "
                                + "scenario",
                        baselinePrecision,
                        reachlayerRanking,
                        baselineRanking)
                .isGreaterThan(baselinePrecision);
    }
}
