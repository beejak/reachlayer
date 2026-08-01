package dev.reachlayer.core.pipeline;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.metrics.PipelineMetrics;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class OrchestratorTest {

    @Test
    void runsFullPipelineAndRendersOutput() {
        ScannerConnector fakeConnector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(
                        Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).build(),
                        Finding.builder().id("f2").source("fake").kind(FindingKind.SCA).build());
            }
        };

        ReachabilityStage reachabilityStage = findings -> findings.stream()
                .map(f -> f.toBuilder().reachability(Reachability.REACHABLE).build())
                .toList();
        EnrichmentStage enrichmentStage = findings -> findings; // no-op for this test
        ScoringStage scoringStage = findings -> findings.stream()
                .map(f -> f.toBuilder().riskScore(f.id().equals("f1") ? 90.0 : 10.0).build())
                .toList();
        AdvisorStage advisorStage = findings -> findings; // no-op for this test

        List<RankedReport> rendered = new ArrayList<>();
        OutputRenderer capturingRenderer = new OutputRenderer() {
            @Override
            public String name() {
                return "capture";
            }

            @Override
            public void render(RankedReport report) {
                rendered.add(report);
            }
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(fakeConnector),
                reachabilityStage,
                enrichmentStage,
                scoringStage,
                advisorStage,
                List.of(capturingRenderer),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");

        assertThat(report.findings()).hasSize(2);
        assertThat(report.findings().get(0).id()).isEqualTo("f1"); // ranked first, higher score
        assertThat(report.findings()).allMatch(f -> f.reachability() == Reachability.REACHABLE);
        assertThat(rendered).containsExactly(report);
    }

    @Test
    void connectorFailureIsSkippedNotThrown() {
        ScannerConnector brokenConnector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "broken";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) throws ConnectorException {
                throw new ConnectorException("boom");
            }
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(brokenConnector),
                findings -> findings,
                findings -> findings,
                findings -> findings,
                findings -> findings,
                List.of(),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");
        assertThat(report.findings()).isEmpty();
    }

    @Test
    void outputFailureDoesNotPropagate() {
        ScannerConnector connector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).build());
            }
        };
        OutputRenderer brokenRenderer = new OutputRenderer() {
            @Override
            public String name() {
                return "broken";
            }

            @Override
            public void render(RankedReport report) throws OutputException {
                throw new OutputException("nope");
            }
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(connector),
                findings -> findings,
                findings -> findings,
                findings -> findings,
                findings -> findings,
                List.of(brokenRenderer),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");
        assertThat(report.findings()).hasSize(1);
    }

    @Test
    void baselineStageTagsFindingsWhenProvidedViaEightArgConstructor() {
        ScannerConnector connector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).build());
            }
        };
        BaselineStage baselineStage =
                findings -> findings.stream().map(f -> f.toBuilder().isNew(true).build()).toList();

        Orchestrator orchestrator = new Orchestrator(
                List.of(connector),
                findings -> findings,
                findings -> findings,
                findings -> findings,
                findings -> findings,
                baselineStage,
                List.of(),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");

        assertThat(report.findings()).allMatch(f -> Boolean.TRUE.equals(f.isNew()));
    }

    @Test
    void sevenArgConstructorLeavesIsNewNullEverywhere() {
        ScannerConnector connector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).build());
            }
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(connector),
                findings -> findings,
                findings -> findings,
                findings -> findings,
                findings -> findings,
                List.of(),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");

        assertThat(report.findings()).allMatch(f -> f.isNew() == null);
    }

    @Test
    void metricsIsNullBeforeRunIsCalled() {
        Orchestrator orchestrator = new Orchestrator(
                List.of(), findings -> findings, findings -> findings, findings -> findings, findings -> findings,
                List.of(), ReachlayerConfig.defaults());

        assertThat(orchestrator.metrics()).isNull();
    }

    @Test
    void metricsRecordsStageDurationsFindingCountsAndRendererOutcomesAfterRun() {
        ScannerConnector connector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(
                        Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).severity("High").build(),
                        Finding.builder().id("f2").source("fake").kind(FindingKind.SCA).severity("Low").build());
            }
        };
        ReachabilityStage reachabilityStage = findings -> findings.stream()
                .map(f -> f.toBuilder().reachability(Reachability.REACHABLE).build())
                .toList();
        OutputRenderer succeedingRenderer = new OutputRenderer() {
            @Override
            public String name() {
                return "ok";
            }

            @Override
            public void render(RankedReport report) {
                // no-op
            }
        };
        OutputRenderer failingRenderer = new OutputRenderer() {
            @Override
            public String name() {
                return "broken";
            }

            @Override
            public void render(RankedReport report) throws OutputException {
                throw new OutputException("render failed");
            }
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(connector),
                reachabilityStage,
                findings -> findings,
                findings -> findings,
                findings -> findings,
                List.of(succeedingRenderer, failingRenderer),
                ReachlayerConfig.defaults());

        orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");

        PipelineMetrics metrics = orchestrator.metrics();
        assertThat(metrics).isNotNull();
        assertThat(metrics.findingsIngested()).isEqualTo(2);
        assertThat(metrics.sourcesRequested()).isEqualTo(1);
        assertThat(metrics.stageDurationMs()).containsKeys("reachability", "enrichment", "scoring", "advisor", "baseline");
        assertThat(metrics.stageErrors()).isEmpty();
        assertThat(metrics.findingCountsBySeverity()).containsEntry("High", 1).containsEntry("Low", 1);
        assertThat(metrics.findingCountsBySource()).containsEntry("fake", 2);
        assertThat(metrics.findingCountsByReachability()).containsEntry("reachable", 2);
        assertThat(metrics.outputRenderersSucceeded()).isEqualTo(1);
        assertThat(metrics.outputRenderersFailed()).isEqualTo(1);
        assertThat(metrics.outputRendererErrors()).containsKey("broken");
        assertThat(metrics.totalDurationMs()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void metricsRecordsStageErrorWhenAStageThrows() {
        ScannerConnector connector = new ScannerConnector() {
            @Override
            public String sourceName() {
                return "fake";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(Finding.builder().id("f1").source("fake").kind(FindingKind.SAST).build());
            }
        };
        ScoringStage throwingScoringStage = findings -> {
            throw new IllegalStateException("scoring exploded");
        };

        Orchestrator orchestrator = new Orchestrator(
                List.of(connector),
                findings -> findings,
                findings -> findings,
                throwingScoringStage,
                findings -> findings,
                List.of(),
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(List.of(ScanSource.ofPath(Path.of("dummy"))), "acme/repo");

        assertThat(report.findings()).hasSize(1); // scoring failure passes findings through unchanged
        assertThat(orchestrator.metrics().stageErrors()).containsEntry("scoring", "scoring exploded");
    }
}
