package dev.reachlayer.evals;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.evals.fixtures.NeverFailScenarios;
import dev.reachlayer.evals.fixtures.ReachabilityCorpus;
import dev.reachlayer.evals.fixtures.ReachabilityCorpus.LabeledCase;
import dev.reachlayer.evals.fixtures.RankingScenario;
import dev.reachlayer.reach.ReachabilityTagger;
import dev.reachlayer.reach.signatures.ComponentLevelSignatureSource;
import dev.reachlayer.scoring.RiskScorer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Regenerates {@code evals/scoreboard.md}, a human-readable summary of the same evals asserted as
 * hard floors by {@code ReachabilityAccuracyEvalTest}, {@code RiskRankingEvalTest}, and {@code
 * NeverFailBuildInvariantTest}. Reuses those tests' fixture/metric building blocks ({@link
 * ReachabilityCorpus}, {@link RankingScenario}, {@link NeverFailScenarios}, {@link Metrics}) so
 * the scoreboard and the hard-floor assertions can never silently drift apart.
 *
 * <p>Run via {@code ./gradlew :evals:runEvals}. Deliberately not part of {@code build}/{@code
 * check} — see {@code docs/testing-strategy.md}.
 */
public final class EvalRunner {

    private EvalRunner() {}

    public static void main(String[] args) throws IOException, java.net.URISyntaxException {
        Path outputPath = resolveOutputPath(args);

        Metrics.ConfusionMatrix reachabilityMatrix = runReachabilityEval();
        RankingResult rankingResult = runRankingEval();
        NeverFailResult neverFailResult = runNeverFailInvariant();

        String scoreboard = renderScoreboard(reachabilityMatrix, rankingResult, neverFailResult);
        if (outputPath.toAbsolutePath().getParent() != null) {
            Files.createDirectories(outputPath.toAbsolutePath().getParent());
        }
        Files.writeString(outputPath, scoreboard);

        System.out.println("Wrote " + outputPath.toAbsolutePath());
    }

    private static Path resolveOutputPath(String[] args) {
        if (args.length > 0 && !args[0].isBlank()) {
            return Path.of(args[0]);
        }
        String systemProperty = System.getProperty("evals.scoreboardPath");
        if (systemProperty != null && !systemProperty.isBlank()) {
            return Path.of(systemProperty);
        }
        return Path.of("evals/scoreboard.md");
    }

    private static Metrics.ConfusionMatrix runReachabilityEval() throws java.net.URISyntaxException {
        List<LabeledCase> corpus = ReachabilityCorpus.cases();
        ReachabilityTagger tagger = new ReachabilityTagger(
                ReachabilityCorpus.classesRoot(), List.of(new ComponentLevelSignatureSource()));

        List<Finding> findings = corpus.stream().map(LabeledCase::finding).toList();
        List<Finding> tagged = tagger.tag(findings);

        // Match by Finding.id() rather than list position: nothing guarantees tagger.tag()
        // preserves input order, so index-based pairing would silently mismatch if it ever
        // reorders or processes findings in parallel.
        Map<String, Finding> taggedById = new LinkedHashMap<>();
        for (Finding finding : tagged) {
            taggedById.put(finding.id(), finding);
        }

        List<Metrics.LabelPair<Reachability>> pairs = new ArrayList<>();
        for (LabeledCase labeledCase : corpus) {
            Finding taggedFinding = taggedById.get(labeledCase.finding().id());
            pairs.add(Metrics.LabelPair.of(taggedFinding.reachability(), labeledCase.expectedLabel()));
        }
        return Metrics.confusionMatrix(pairs, Reachability.REACHABLE);
    }

    private static RankingResult runRankingEval() {
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
        return new RankingResult(baselinePrecision, reachlayerPrecision);
    }

    /**
     * Re-runs the exact same adversarial {@link Orchestrator} wiring as {@code
     * NeverFailBuildInvariantTest} and records whether any scenario let an exception escape.
     */
    private static NeverFailResult runNeverFailInvariant() {
        Map<String, Orchestrator> scenarios = NeverFailScenarios.scenarios();
        List<String> failures = new ArrayList<>();
        for (Map.Entry<String, Orchestrator> entry : scenarios.entrySet()) {
            // Catches Throwable, not just RuntimeException: NeverFailBuildInvariantTest uses
            // AssertJ's assertThatCode(...).doesNotThrowAnyException(), which intercepts any
            // Throwable including Error subclasses (StackOverflowError, OutOfMemoryError,
            // AssertionError). A narrower catch here would let an Error crash scoreboard
            // generation instead of recording a FAIL entry, so this runner and the JUnit hard
            // floor would disagree about the same run. Recording a FAIL and moving on -- never
            // rethrowing -- is exactly the "never fail the build" principle this suite exists to
            // verify (PLAN.md §2 principle 1 / README.md design principles).
            try {
                entry.getValue().run(List.of(ScanSource.ofPath(Path.of("test/repo"))), "test/repo");
            } catch (Throwable e) {
                failures.add(entry.getKey() + " -> " + e.getClass().getSimpleName() + ": "
                        + (e.getMessage() != null ? e.getMessage() : "(no message)"));
            }
        }
        return new NeverFailResult(scenarios.size(), failures);
    }

    private static String renderScoreboard(
            Metrics.ConfusionMatrix reachabilityMatrix, RankingResult rankingResult, NeverFailResult neverFailResult) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Reachlayer eval scoreboard\n\n");
        sb.append("_Generated: ").append(Instant.now()).append("_\n\n");
        sb.append("See `docs/testing-strategy.md` for what this measures and why it's separate ")
                .append("from unit tests.\n\n");

        sb.append("## Reachability tagging accuracy\n\n");
        sb.append("Corpus: `ReachabilityCorpus` (").append(reachabilityMatrix.total())
                .append(" labeled case(s)). Positive label = `REACHABLE`.\n\n");
        sb.append("| Metric | Count |\n");
        sb.append("|---|---|\n");
        sb.append("| True positives (reachable, correctly tagged reachable) | ")
                .append(reachabilityMatrix.truePositives()).append(" |\n");
        sb.append("| False positives (not-reachable ground truth, tagged reachable) | ")
                .append(reachabilityMatrix.falsePositives()).append(" |\n");
        sb.append("| True negatives (not-reachable, correctly not tagged reachable) | ")
                .append(reachabilityMatrix.trueNegatives()).append(" |\n");
        sb.append("| False negatives (reachable ground truth, NOT tagged reachable) | ")
                .append(reachabilityMatrix.falseNegatives()).append(" |\n\n");
        sb.append("Hard floor (`ReachabilityAccuracyEvalTest`): zero `REACHABLE`-labeled cases are ")
                .append("ever tagged `UNREACHABLE` — under-claiming unreachability is the safe ")
                .append("direction (PLAN.md §9 risk 1).\n\n");

        sb.append("## Risk ranking: Reachlayer vs. naive CVSS-only baseline\n\n");
        sb.append("Scenario: `RankingScenario` (6 hand-crafted findings), scored against a ")
                .append("hand-labeled ground-truth top-3.\n\n");
        sb.append("| Ranking | Precision@3 |\n");
        sb.append("|---|---|\n");
        sb.append("| CVSS-only baseline | ").append(format(rankingResult.baselinePrecision())).append(" |\n");
        sb.append("| Reachlayer (`RiskScorer`) | ").append(format(rankingResult.reachlayerPrecision())).append(" |\n\n");
        sb.append("Hard floor (`RiskRankingEvalTest`): Reachlayer's precision@3 must be strictly ")
                .append("greater than the CVSS-only baseline's on this scenario.\n\n");

        sb.append("## Never-fail-build invariant\n\n");
        sb.append("Scenarios exercised: ").append(neverFailResult.scenarioCount()).append("\n\n");
        if (neverFailResult.failures().isEmpty()) {
            sb.append("**PASS** — no scenario let an exception escape `Orchestrator.run` ")
                    .append("(PLAN.md §2 principle 1).\n");
        } else {
            sb.append("**FAIL** — the following scenario(s) let an exception escape:\n\n");
            for (String failure : neverFailResult.failures()) {
                sb.append("- ").append(failure).append("\n");
            }
        }

        return sb.toString();
    }

    private static String format(double value) {
        return String.format(java.util.Locale.ROOT, "%.2f", value);
    }

    private record RankingResult(double baselinePrecision, double reachlayerPrecision) {}

    private record NeverFailResult(int scenarioCount, List<String> failures) {}
}
