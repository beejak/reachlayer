package dev.reachlayer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.advisor.api.FixAdvisorService;
import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.connectors.blackduck.BlackDuckConnector;
import dev.reachlayer.connectors.fortify.FortifyConnector;
import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.metrics.PipelineMetrics;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.pipeline.ScoringStage;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import dev.reachlayer.fixtures.corpusgen.CorpusGenerator;
import dev.reachlayer.fixtures.corpusgen.GeneratedCorpus;
import dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent;
import dev.reachlayer.scoring.RiskScorer;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The "evaluation pipeline" (see {@code docs/evaluation-pipeline.md}): runs the full Reachlayer
 * pipeline against a larger, varied synthetic corpus ({@link CorpusGenerator}) with {@code
 * --classes} pointed at {@code fixtures:vulnerable-spring-app}'s real compiled bytecode. Unlike
 * every other CLI-wiring test in this repo (which passes an empty classes dir, so reachability
 * always degrades to identity/{@code UNKNOWN}), this test proves the full pipeline produces
 * genuine {@code REACHABLE}/{@code UNREACHABLE} signal end-to-end, at a scale (100+ findings) that
 * exercises sorting, top-N pagination, SARIF rule dedup, and metrics collection the way a
 * real-world finding volume would -- not just the 5-finding golden-path fixture.
 */
class EvaluationCorpusIT {

    private Path repoRoot() {
        return Path.of("").toAbsolutePath().getParent();
    }

    private Path fixtureClassesRoot() throws URISyntaxException {
        return Paths.get(
                ReachableVulnerableComponent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    @Test
    void fullPipelineAgainstLargerSyntheticCorpusProducesGenuineReachabilitySignalAndValidOutputs(
            @TempDir Path tempDir) throws Exception {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);
        Path fortifyExport = tempDir.resolve("audit.fvdl");
        Path blackduckExport = tempDir.resolve("scan.json");
        Files.writeString(fortifyExport, corpus.fvdlXml());
        Files.writeString(blackduckExport, corpus.blackDuckJson());

        List<ScanSource> sources = List.of(ScanSource.ofPath(fortifyExport), ScanSource.ofPath(blackduckExport));
        List<ScannerConnector> connectors = List.of(new FortifyConnector(), new BlackDuckConnector());

        ReachabilityStage reachabilityStage = Main.buildReachabilityStage(fixtureClassesRoot().toString());
        EnrichmentStage enrichmentStage = Main.buildEnrichmentStage(
                uri -> "{\"status\":\"OK\",\"data\":[]}", // fake EPSS fetcher: no data, never throws
                uri -> "{\"vulnerabilities\":[]}", // fake KEV fetcher: empty catalog, never throws
                tempDir.resolve("cache"));
        ScoringStage scoringStage = findings -> new RiskScorer().score(findings, ReachlayerConfig.defaults().scoring());
        AdvisorStage advisorStage = new FixAdvisorService(
                Main.buildProvider("noop"), ReachlayerConfig.defaults().advisor(), new ContextBuilder(), repoRoot());

        Path outFile = tempDir.resolve("report.md");
        Path sarifFile = tempDir.resolve("report.sarif");
        List<OutputRenderer> outputRenderers = Main.buildOutputRenderers(outFile, false, sarifFile);

        Orchestrator orchestrator = new Orchestrator(
                connectors,
                reachabilityStage,
                enrichmentStage,
                scoringStage,
                advisorStage,
                outputRenderers,
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(sources, "reachlayer/evaluation-corpus");

        int expectedTotal = corpus.sastFindingCount() + corpus.scaFindingCount();
        assertThat(report.findings()).hasSize(expectedTotal);

        // The real point of this test: genuine reachability signal, not the UNKNOWN-only outcome
        // every other CLI-wiring test in this repo exercises (they all pass an empty --classes).
        Map<Reachability, Long> byReachability =
                report.findings().stream().collect(Collectors.groupingBy(Finding::reachability, Collectors.counting()));
        assertThat(byReachability.getOrDefault(Reachability.REACHABLE, 0L))
                .as("the ReachableVulnerableComponent/VulnerableController anchors should tag REACHABLE")
                .isGreaterThanOrEqualTo(1);
        assertThat(byReachability.getOrDefault(Reachability.UNREACHABLE, 0L))
                .as("the UnreachableVulnerableComponent anchor should tag UNREACHABLE")
                .isGreaterThanOrEqualTo(1);
        assertThat(byReachability.getOrDefault(Reachability.UNKNOWN, 0L))
                .as("bulk synthetic findings, not part of the analyzed app, should tag UNKNOWN")
                .isGreaterThanOrEqualTo(1);

        assertThat(report.findings()).allSatisfy(f -> assertThat(f.riskScore()).isNotNull());

        assertThat(outFile).exists();
        assertThat(sarifFile).exists();
        String sarifJson = Files.readString(sarifFile);
        assertThat(sarifJson).contains("\"version\" : \"2.1.0\"");

        PipelineMetrics metrics = orchestrator.metrics();
        assertThat(metrics).isNotNull();
        assertThat(metrics.findingsIngested()).isEqualTo(expectedTotal);
        assertThat(metrics.stageDurationMs()).containsKeys("reachability", "enrichment", "scoring", "advisor");
    }
}
