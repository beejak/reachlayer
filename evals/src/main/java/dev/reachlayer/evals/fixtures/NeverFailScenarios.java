package dev.reachlayer.evals.fixtures;

import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.pipeline.ScoringStage;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Adversarial {@link Orchestrator} wiring shared by {@code NeverFailBuildInvariantTest} (the hard
 * JUnit floor) and {@link dev.reachlayer.evals.EvalRunner} (the scoreboard), kept in exactly one
 * place so the two can never drift apart.
 *
 * <p>Each named scenario deliberately breaks exactly one collaborator (always throwing), plus one
 * scenario that breaks everything at once. Per PLAN.md §2 principle 1 ("never fail or block the
 * build"), {@link Orchestrator#run} must never let an exception escape regardless of which
 * collaborator misbehaves — {@code Orchestrator}'s own {@code safeStage}/{@code renderAll}
 * already guard every stage and renderer, so every scenario here is expected to currently pass.
 */
public final class NeverFailScenarios {

    private NeverFailScenarios() {}

    /** Ordered scenario name -&gt; the {@link Orchestrator} wired with that scenario's broken piece(s). */
    public static Map<String, Orchestrator> scenarios() {
        Map<String, Orchestrator> scenarios = new LinkedHashMap<>();

        scenarios.put(
                "connector always throws",
                new Orchestrator(
                        List.of(brokenConnector()),
                        okReachability(),
                        okEnrichment(),
                        okScoring(),
                        okAdvisor(),
                        List.of(okRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "reachability stage always throws",
                new Orchestrator(
                        List.of(okConnector()),
                        brokenReachability(),
                        okEnrichment(),
                        okScoring(),
                        okAdvisor(),
                        List.of(okRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "enrichment stage always throws",
                new Orchestrator(
                        List.of(okConnector()),
                        okReachability(),
                        brokenEnrichment(),
                        okScoring(),
                        okAdvisor(),
                        List.of(okRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "scoring stage always throws",
                new Orchestrator(
                        List.of(okConnector()),
                        okReachability(),
                        okEnrichment(),
                        brokenScoring(),
                        okAdvisor(),
                        List.of(okRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "advisor stage always throws",
                new Orchestrator(
                        List.of(okConnector()),
                        okReachability(),
                        okEnrichment(),
                        okScoring(),
                        brokenAdvisor(),
                        List.of(okRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "output renderer always throws",
                new Orchestrator(
                        List.of(okConnector()),
                        okReachability(),
                        okEnrichment(),
                        okScoring(),
                        okAdvisor(),
                        List.of(brokenRenderer()),
                        ReachlayerConfig.defaults()));

        scenarios.put(
                "everything broken at once",
                new Orchestrator(
                        List.of(brokenConnector(), okConnector()),
                        brokenReachability(),
                        brokenEnrichment(),
                        brokenScoring(),
                        brokenAdvisor(),
                        List.of(brokenRenderer(), okRenderer()),
                        ReachlayerConfig.defaults()));

        return scenarios;
    }

    private static ReachabilityStage okReachability() {
        return findings -> findings;
    }

    private static ReachabilityStage brokenReachability() {
        return findings -> {
            throw new RuntimeException("reachability stage always fails");
        };
    }

    private static EnrichmentStage okEnrichment() {
        return findings -> findings;
    }

    private static EnrichmentStage brokenEnrichment() {
        return findings -> {
            throw new RuntimeException("enrichment stage always fails");
        };
    }

    private static ScoringStage okScoring() {
        return findings -> findings;
    }

    private static ScoringStage brokenScoring() {
        return findings -> {
            throw new RuntimeException("scoring stage always fails");
        };
    }

    private static AdvisorStage okAdvisor() {
        return findings -> findings;
    }

    private static AdvisorStage brokenAdvisor() {
        return findings -> {
            throw new RuntimeException("advisor stage always fails");
        };
    }

    private static ScannerConnector okConnector() {
        return new ScannerConnector() {
            @Override
            public String sourceName() {
                return "ok";
            }

            @Override
            public boolean supports(ScanSource source) {
                return true;
            }

            @Override
            public List<Finding> ingest(ScanSource source) {
                return List.of(Finding.builder().id("f1").source("ok").kind(FindingKind.SAST).build());
            }
        };
    }

    private static ScannerConnector brokenConnector() {
        return new ScannerConnector() {
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
                throw new ConnectorException("connector always fails");
            }
        };
    }

    private static OutputRenderer okRenderer() {
        return new OutputRenderer() {
            @Override
            public String name() {
                return "ok";
            }

            @Override
            public void render(RankedReport report) {
                // no-op
            }
        };
    }

    private static OutputRenderer brokenRenderer() {
        return new OutputRenderer() {
            @Override
            public String name() {
                return "broken";
            }

            @Override
            public void render(RankedReport report) throws OutputException {
                throw new OutputException("renderer always fails");
            }
        };
    }
}
