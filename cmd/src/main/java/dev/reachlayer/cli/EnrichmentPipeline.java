package dev.reachlayer.cli;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer;
import dev.reachlayer.enrich.epss.EpssClient;
import dev.reachlayer.enrich.kev.KevClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Composes the three independent {@code enrich} clients ({@link EpssClient}, {@link KevClient},
 * {@link BlastRadiusAnalyzer}) into a single {@link EnrichmentStage}. No {@code enrich}
 * submodule depends on the others, and none of them implement {@code EnrichmentStage} directly
 * — {@code cmd} is the only module that depends on all three, so the composition lives here.
 *
 * <p>EPSS lookups are batched: every distinct primary CVE across the whole input list is looked
 * up in a single {@link EpssClient#lookup(List)} call, rather than one HTTP round trip per
 * finding. KEV membership is likewise looked up once via {@link KevClient#knownExploitedCves()}
 * and checked in-memory per finding, rather than calling {@link KevClient#isKnownExploited(String)}
 * per finding — that method re-reads and re-parses the on-disk KEV cache file on every call, which
 * previously meant one redundant disk read + JSON parse per finding (see
 * docs/architecture-optimization.md §3.2).
 */
public final class EnrichmentPipeline implements EnrichmentStage {

    private final EpssClient epssClient;
    private final KevClient kevClient;
    private final BlastRadiusAnalyzer blastRadiusAnalyzer;

    public EnrichmentPipeline(EpssClient epssClient, KevClient kevClient, BlastRadiusAnalyzer blastRadiusAnalyzer) {
        this.epssClient = Objects.requireNonNull(epssClient, "epssClient");
        this.kevClient = Objects.requireNonNull(kevClient, "kevClient");
        this.blastRadiusAnalyzer = Objects.requireNonNull(blastRadiusAnalyzer, "blastRadiusAnalyzer");
    }

    @Override
    public List<Finding> enrich(List<Finding> findings) {
        List<String> cveIds = findings.stream()
                .map(EnrichmentPipeline::primaryCve)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        Map<String, Epss> epssByCve = epssClient.lookup(cveIds);
        Set<String> knownExploitedCves = kevClient.knownExploitedCves();

        List<Finding> result = new ArrayList<>(findings.size());
        for (Finding finding : findings) {
            String cve = primaryCve(finding);
            Epss epss = cve == null ? null : epssByCve.get(cve);
            boolean kev = cve != null && knownExploitedCves.contains(cve);
            BlastRadius blastRadius = blastRadiusAnalyzer.analyze(finding);
            result.add(finding.toBuilder().epss(epss).kev(kev).blastRadius(blastRadius).build());
        }
        return result;
    }

    private static String primaryCve(Finding finding) {
        List<String> cve = finding.cve();
        return cve.isEmpty() ? null : cve.get(0);
    }
}
