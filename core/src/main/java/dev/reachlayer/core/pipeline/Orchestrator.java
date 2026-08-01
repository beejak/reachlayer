package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.metrics.PipelineMetrics;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wires the full pipeline: ingest -&gt; reachability -&gt; enrich -&gt; score -&gt; advise -&gt; output.
 *
 * <p>Every stage is injected via its constructor (plain constructor injection — no DI framework
 * needed at this scale). {@link ScannerConnector} and {@link OutputRenderer} are the real SPI
 * interfaces; the middle stages use the small functional interfaces in this package so that
 * {@code core} does not need to depend on the {@code reachability}/{@code enrich}/
 * {@code scoring}/{@code advisor} modules.
 *
 * <p>Per PLAN.md §2.1, the orchestrator never lets a single connector or renderer failure abort
 * the run: ingestion errors are logged and skipped, and output errors are logged, never thrown
 * as a build failure.
 */
public final class Orchestrator {

    private static final Logger log = LoggerFactory.getLogger(Orchestrator.class);

    private final List<ScannerConnector> connectors;
    private final ReachabilityStage reachabilityStage;
    private final EnrichmentStage enrichmentStage;
    private final ScoringStage scoringStage;
    private final AdvisorStage advisorStage;
    private final BaselineStage baselineStage;
    private final List<OutputRenderer> outputRenderers;
    private final ReachlayerConfig config;

    private volatile PipelineMetrics metrics;

    public Orchestrator(
            List<ScannerConnector> connectors,
            ReachabilityStage reachabilityStage,
            EnrichmentStage enrichmentStage,
            ScoringStage scoringStage,
            AdvisorStage advisorStage,
            List<OutputRenderer> outputRenderers,
            ReachlayerConfig config) {
        this(connectors, reachabilityStage, enrichmentStage, scoringStage, advisorStage, null, outputRenderers, config);
    }

    /**
     * Overload accepting a {@link BaselineStage} (PLAN.md §5 Phase 1, "baseline/diff mode"). {@code
     * baselineStage} may be {@code null} — treated identically to the 7-arg constructor above (no
     * tagging occurs; every finding's {@code isNew()} stays {@code null}) — so this overload is
     * purely additive: every existing call site using the 7-arg constructor keeps compiling and
     * behaving exactly as before.
     */
    public Orchestrator(
            List<ScannerConnector> connectors,
            ReachabilityStage reachabilityStage,
            EnrichmentStage enrichmentStage,
            ScoringStage scoringStage,
            AdvisorStage advisorStage,
            BaselineStage baselineStage,
            List<OutputRenderer> outputRenderers,
            ReachlayerConfig config) {
        this.connectors = List.copyOf(connectors);
        this.reachabilityStage = reachabilityStage;
        this.enrichmentStage = enrichmentStage;
        this.scoringStage = scoringStage;
        this.advisorStage = advisorStage;
        this.baselineStage = baselineStage == null ? findings -> findings : baselineStage;
        this.outputRenderers = List.copyOf(outputRenderers);
        this.config = config;
    }

    /** Ingests every source, runs the pipeline, renders the report, and returns it. */
    public RankedReport run(List<ScanSource> sources, String repoLabel) {
        Instant startedAt = Instant.now();
        long runStartNanos = System.nanoTime();
        Map<String, Long> stageDurationMs = new LinkedHashMap<>();
        Map<String, String> stageErrors = new LinkedHashMap<>();

        List<Finding> findings = ingest(sources);
        int findingsIngested = findings.size();
        log.info("Ingested {} findings from {} source(s)", findingsIngested, sources.size());

        List<Finding> afterReachability = findings;
        findings = timedStage(
                "reachability", () -> reachabilityStage.tag(afterReachability), findings, stageDurationMs, stageErrors);
        List<Finding> afterEnrichment = findings;
        findings = timedStage(
                "enrichment", () -> enrichmentStage.enrich(afterEnrichment), findings, stageDurationMs, stageErrors);
        List<Finding> afterScoring = findings;
        findings = timedStage(
                "scoring", () -> scoringStage.score(afterScoring), findings, stageDurationMs, stageErrors);
        List<Finding> afterAdvisor = findings;
        findings = timedStage(
                "advisor", () -> advisorStage.advise(afterAdvisor), findings, stageDurationMs, stageErrors);

        List<Finding> afterBaseline = findings;
        findings = timedStage(
                "baseline", () -> baselineStage.tag(afterBaseline), findings, stageDurationMs, stageErrors);

        RankedReport report = RankedReport.of(findings, repoLabel, config.output().topN());
        RenderSummary renderSummary = renderAll(report);

        long totalDurationMs = (System.nanoTime() - runStartNanos) / 1_000_000;
        this.metrics = new PipelineMetrics(
                startedAt,
                Instant.now(),
                totalDurationMs,
                sources.size(),
                findingsIngested,
                stageDurationMs,
                stageErrors,
                countBy(findings, Finding::severity),
                countBy(findings, Finding::source),
                countBy(findings, f -> f.reachability() == null ? "unknown" : f.reachability().wireValue()),
                renderSummary.succeeded(),
                outputRenderers.size() - renderSummary.succeeded(),
                renderSummary.errors());

        return report;
    }

    /** Metrics from the most recent {@link #run}; {@code null} until a run has completed. */
    public PipelineMetrics metrics() {
        return metrics;
    }

    private static Map<String, Integer> countBy(List<Finding> findings, java.util.function.Function<Finding, String> key) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Finding f : findings) {
            String k = key.apply(f);
            counts.merge(k == null ? "unknown" : k, 1, Integer::sum);
        }
        return counts;
    }

    private List<Finding> ingest(List<ScanSource> sources) {
        List<Finding> findings = new ArrayList<>();
        for (ScanSource source : sources) {
            boolean handled = false;
            for (ScannerConnector connector : connectors) {
                if (!connector.supports(source)) {
                    continue;
                }
                handled = true;
                try {
                    List<Finding> ingested = connector.ingest(source);
                    log.info(
                            "Connector '{}' ingested {} finding(s) from {}",
                            connector.sourceName(),
                            ingested.size(),
                            source.path());
                    findings.addAll(ingested);
                } catch (ConnectorException e) {
                    log.warn(
                            "Connector '{}' failed to ingest {}: {}",
                            connector.sourceName(),
                            source.path(),
                            e.getMessage(),
                            e);
                }
            }
            if (!handled) {
                log.warn("No connector claims to support source {}", source.path());
            }
        }
        return findings;
    }

    private List<Finding> timedStage(
            String name,
            Supplier<List<Finding>> stage,
            List<Finding> fallback,
            Map<String, Long> stageDurationMs,
            Map<String, String> stageErrors) {
        long start = System.nanoTime();
        try {
            return stage.get();
        } catch (RuntimeException e) {
            log.warn("Pipeline stage '{}' failed, passing findings through unchanged: {}", name, e.getMessage(), e);
            stageErrors.put(name, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            return fallback;
        } finally {
            stageDurationMs.put(name, (System.nanoTime() - start) / 1_000_000);
        }
    }

    private RenderSummary renderAll(RankedReport report) {
        int succeeded = 0;
        Map<String, String> errors = new LinkedHashMap<>();
        for (OutputRenderer renderer : outputRenderers) {
            try {
                renderer.render(report);
                succeeded++;
            } catch (OutputException | RuntimeException e) {
                log.warn("Output renderer '{}' failed: {}", renderer.name(), e.getMessage(), e);
                errors.put(renderer.name(), e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
        }
        return new RenderSummary(succeeded, errors);
    }

    private record RenderSummary(int succeeded, Map<String, String> errors) {
    }
}
