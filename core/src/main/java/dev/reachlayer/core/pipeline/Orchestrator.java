package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.util.ArrayList;
import java.util.List;
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
        List<Finding> findings = ingest(sources);
        log.info("Ingested {} findings from {} source(s)", findings.size(), sources.size());

        List<Finding> afterReachability = findings;
        findings = safeStage("reachability", () -> reachabilityStage.tag(afterReachability), findings);
        List<Finding> afterEnrichment = findings;
        findings = safeStage("enrichment", () -> enrichmentStage.enrich(afterEnrichment), findings);
        List<Finding> afterScoring = findings;
        findings = safeStage("scoring", () -> scoringStage.score(afterScoring), findings);
        List<Finding> afterAdvisor = findings;
        findings = safeStage("advisor", () -> advisorStage.advise(afterAdvisor), findings);

        List<Finding> afterBaseline = findings;
        findings = safeStage("baseline", () -> baselineStage.tag(afterBaseline), findings);

        RankedReport report = RankedReport.of(findings, repoLabel, config.output().topN());
        renderAll(report);
        return report;
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

    private List<Finding> safeStage(String name, java.util.function.Supplier<List<Finding>> stage, List<Finding> fallback) {
        try {
            return stage.get();
        } catch (RuntimeException e) {
            log.warn("Pipeline stage '{}' failed, passing findings through unchanged: {}", name, e.getMessage(), e);
            return fallback;
        }
    }

    private void renderAll(RankedReport report) {
        for (OutputRenderer renderer : outputRenderers) {
            try {
                renderer.render(report);
            } catch (OutputException | RuntimeException e) {
                log.warn("Output renderer '{}' failed: {}", renderer.name(), e.getMessage(), e);
            }
        }
    }
}
