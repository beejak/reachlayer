package dev.reachlayer.evals;

import dev.reachlayer.core.model.Finding;
import java.util.List;
import java.util.Set;

/**
 * Small, dependency-free metric helpers shared by the eval tests and {@link EvalRunner}. Kept
 * generic and free of any {@code core}/{@code reachability}/{@code scoring} imports so it stays
 * trivially reusable across whatever eval gets added next.
 */
public final class Metrics {

    private Metrics() {}

    /** One (predicted, actual) label observation fed into {@link #confusionMatrix}. */
    public record LabelPair<T>(T predicted, T actual) {
        public static <T> LabelPair<T> of(T predicted, T actual) {
            return new LabelPair<>(predicted, actual);
        }
    }

    /** TP/FP/TN/FN counts against a chosen "positive" label. */
    public record ConfusionMatrix(int truePositives, int falsePositives, int trueNegatives, int falseNegatives) {

        public int total() {
            return truePositives + falsePositives + trueNegatives + falseNegatives;
        }

        /** {@code TP / (TP + FN)}, or {@code 0.0} if there are no actual-positive cases. */
        public double recall() {
            int denominator = truePositives + falseNegatives;
            return denominator == 0 ? 0.0 : (double) truePositives / denominator;
        }

        /** {@code TP / (TP + FP)}, or {@code 0.0} if nothing was predicted positive. */
        public double precision() {
            int denominator = truePositives + falsePositives;
            return denominator == 0 ? 0.0 : (double) truePositives / denominator;
        }
    }

    /**
     * Counts a confusion matrix over {@code pairs} against {@code positiveLabel}: any label equal
     * to {@code positiveLabel} counts as "positive", anything else (including other enum values,
     * e.g. {@code UNKNOWN} alongside {@code REACHABLE}/{@code UNREACHABLE}) counts as "negative".
     */
    public static <T> ConfusionMatrix confusionMatrix(List<LabelPair<T>> pairs, T positiveLabel) {
        int tp = 0;
        int fp = 0;
        int tn = 0;
        int fn = 0;
        for (LabelPair<T> pair : pairs) {
            boolean predictedPositive = positiveLabel.equals(pair.predicted());
            boolean actualPositive = positiveLabel.equals(pair.actual());
            if (predictedPositive && actualPositive) {
                tp++;
            } else if (predictedPositive) {
                fp++;
            } else if (actualPositive) {
                fn++;
            } else {
                tn++;
            }
        }
        return new ConfusionMatrix(tp, fp, tn, fn);
    }

    /**
     * Fraction of the top-{@code k} entries of {@code rankedIds} that appear in {@code
     * groundTruthTopIds}. If {@code rankedIds} has fewer than {@code k} entries, precision is
     * computed over however many are actually present. Returns {@code 0.0} for {@code k <= 0} or
     * an empty ranking.
     */
    public static double precisionAtK(List<String> rankedIds, Set<String> groundTruthTopIds, int k) {
        if (k <= 0 || rankedIds.isEmpty()) {
            return 0.0;
        }
        int effectiveK = Math.min(k, rankedIds.size());
        long hits = rankedIds.stream().limit(effectiveK).filter(groundTruthTopIds::contains).count();
        return (double) hits / effectiveK;
    }

    /**
     * {@code finding.cvss().score()} if the finding carries a known CVSS score, {@code 0.0}
     * otherwise. Shared by {@link EvalRunner} and {@code RiskRankingEvalTest} so both rank findings
     * with unknown CVSS identically (previously duplicated privately in each).
     */
    static double cvssOrZero(Finding finding) {
        return finding.cvss() != null && finding.cvss().isKnown() ? finding.cvss().score() : 0.0;
    }
}
