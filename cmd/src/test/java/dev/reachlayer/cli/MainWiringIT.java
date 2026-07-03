package dev.reachlayer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.advisor.api.FixAdvisorService;
import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.connectors.blackduck.BlackDuckConnector;
import dev.reachlayer.connectors.fortify.FortifyConnector;
import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.pipeline.ScoringStage;
import dev.reachlayer.core.spi.LlmProvider;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import dev.reachlayer.scoring.RiskScorer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises {@link Main}'s package-private wiring methods against the real
 * {@code fixtures/sample-fpr} and {@code fixtures/sample-bdio} exports, with fake
 * {@code HttpFetcher}s standing in for live EPSS/KEV network calls (never touch the network
 * from an automated test — same rule every other module's tests already follow). This proves
 * the wiring in {@link Main} actually produces a full, scored, rendered report end-to-end;
 * {@code Main.main(String[])} itself is not invoked here (that would require a real process
 * exit), but every piece it assembles is exercised through the exact same package-private
 * factory methods {@code Main.call()} calls.
 */
class MainWiringIT {

    /**
     * The repo root, resolved relative to this module's own source tree — {@code cmd}'s Gradle
     * project directory is {@code <repoRoot>/cmd}, so the parent directory is the repo root
     * where {@code fixtures/} lives.
     */
    private Path repoRoot() {
        return Path.of("").toAbsolutePath().getParent();
    }

    @Test
    void runsFullPipelineAgainstRealFixturesAndProducesAScoredRenderedReport(@TempDir Path tempDir) throws IOException {
        Path fortifyExport = repoRoot().resolve("fixtures/sample-fpr/audit.fvdl");
        Path blackduckExport = repoRoot().resolve("fixtures/sample-bdio/scan.json");
        assertThat(fortifyExport).exists();
        assertThat(blackduckExport).exists();

        List<ScanSource> sources =
                List.of(ScanSource.ofPath(fortifyExport), ScanSource.ofPath(blackduckExport));
        List<ScannerConnector> connectors = List.of(new FortifyConnector(), new BlackDuckConnector());

        ReachabilityStage reachabilityStage = Main.buildReachabilityStage(""); // no classes dir: identity passthrough
        EnrichmentStage enrichmentStage = Main.buildEnrichmentStage(
                uri -> "{\"status\":\"OK\",\"data\":[]}", // fake EPSS fetcher: no data, never throws
                uri -> "{\"vulnerabilities\":[]}", // fake KEV fetcher: empty catalog, never throws
                tempDir.resolve("cache"));
        ScoringStage scoringStage = findings -> new RiskScorer().score(findings, ReachlayerConfig.defaults().scoring());
        LlmProvider provider = Main.buildProvider("noop");
        AdvisorStage advisorStage =
                new FixAdvisorService(provider, ReachlayerConfig.defaults().advisor(), new ContextBuilder(), repoRoot());

        Path outFile = tempDir.resolve("report.md");
        List<OutputRenderer> outputRenderers = Main.buildOutputRenderers(outFile, false); // no GitHub env vars in CI

        Orchestrator orchestrator = new Orchestrator(
                connectors,
                reachabilityStage,
                enrichmentStage,
                scoringStage,
                advisorStage,
                outputRenderers,
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(sources, "reachlayer/reachlayer");

        assertThat(report.findings()).hasSize(5); // 2 SAST from Fortify + 3 SCA from Black Duck
        assertThat(report.findings()).allSatisfy(f -> {
            assertThat(f.riskScore()).isNotNull();
            assertThat(f.riskExplanation()).isNotNull();
            assertThat(f.fixSuggestion()).isNotNull();
            assertThat(f.reachability()).isNotNull(); // UNKNOWN, since no --classes was given
        });

        List<String> allCves = new ArrayList<>();
        report.findings().forEach(f -> allCves.addAll(f.cve()));
        assertThat(allCves)
                .containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2021-35516", "CVE-2019-12384");

        assertThat(outFile).exists();
        String written = Files.readString(outFile);
        assertThat(written).contains("reachlayer:report"); // the default comment marker
        assertThat(written).contains("reachlayer/reachlayer");
    }

    @Test
    void classesDirEmptyMeansIdentityReachabilityStage() {
        ReachabilityStage stage = Main.buildReachabilityStage("");
        Finding input = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> tagged = stage.tag(List.of(input));

        assertThat(tagged).containsExactly(input); // identity: same reference, unchanged
    }

    @Test
    void buildProviderSelectsAnthropicOnlyWhenConfigured() {
        assertThat(Main.buildProvider("noop")).isInstanceOf(dev.reachlayer.advisor.providers.noop.NoopLlmProvider.class);
        assertThat(Main.buildProvider("anything-else"))
                .isInstanceOf(dev.reachlayer.advisor.providers.noop.NoopLlmProvider.class);
        assertThat(Main.buildProvider("anthropic"))
                .isInstanceOf(dev.reachlayer.advisor.providers.anthropic.AnthropicLlmProvider.class);
    }

    @Test
    void firstNonBlankPrefersPreferredValue() {
        assertThat(Main.firstNonBlank("a", "b")).isEqualTo("a");
        assertThat(Main.firstNonBlank("", "b")).isEqualTo("b");
        assertThat(Main.firstNonBlank(null, "b")).isEqualTo("b");
    }
}
