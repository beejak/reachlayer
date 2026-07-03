package dev.reachlayer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer;
import dev.reachlayer.enrich.epss.EpssClient;
import dev.reachlayer.enrich.kev.KevClient;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EnrichmentPipelineTest {

    private static final String EPSS_RESPONSE =
            """
            {
              "status": "OK",
              "data": [
                { "cve": "CVE-2021-44228", "epss": "0.974730000", "percentile": "0.999720000", "date": "2024-01-01" },
                { "cve": "CVE-2021-35516", "epss": "0.012340000", "percentile": "0.500000000", "date": "2024-01-01" }
              ]
            }
            """;

    private static final String KEV_RESPONSE =
            """
            {
              "catalogVersion": "2024.06.01",
              "dateReleased": "2024-06-01T00:00:00.000Z",
              "count": 1,
              "vulnerabilities": [
                { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j" }
              ]
            }
            """;

    @TempDir
    Path tempDir;

    private Finding findingWithCve(String id, String cve) {
        return Finding.builder()
                .id(id)
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(Component.of("some-lib", "1.0.0"))
                .cve(cve == null ? List.of() : List.of(cve))
                .build();
    }

    @Test
    void batchesEpssLookupAcrossAllFindingsInOneFetch() {
        AtomicInteger epssFetchCount = new AtomicInteger();
        EpssClient epssClient = new EpssClient(
                uri -> {
                    epssFetchCount.incrementAndGet();
                    return EPSS_RESPONSE;
                },
                tempDir,
                () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        List<Finding> findings = List.of(
                findingWithCve("f1", "CVE-2021-44228"), findingWithCve("f2", "CVE-2021-35516"));

        List<Finding> enriched = pipeline.enrich(findings);

        assertThat(epssFetchCount.get()).isEqualTo(1);
        Epss f1Epss = enriched.get(0).epss();
        assertThat(f1Epss).isNotNull();
        assertThat(f1Epss.score()).isEqualTo(0.97473);
        Epss f2Epss = enriched.get(1).epss();
        assertThat(f2Epss).isNotNull();
        assertThat(f2Epss.percentile()).isEqualTo(0.5);
    }

    @Test
    void attachesKevFlagOnlyForKnownExploitedCve() {
        EpssClient epssClient = new EpssClient(uri -> EPSS_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        List<Finding> findings = List.of(
                findingWithCve("f1", "CVE-2021-44228"), findingWithCve("f2", "CVE-2021-35516"));

        List<Finding> enriched = pipeline.enrich(findings);

        assertThat(enriched.get(0).kev()).isTrue();
        assertThat(enriched.get(1).kev()).isFalse();
    }

    @Test
    void findingWithNoCveGetsNullEpssAndFalseKevButStillGetsBlastRadius() {
        EpssClient epssClient = new EpssClient(
                uri -> {
                    throw new AssertionError("EPSS should never be fetched when no finding has a CVE");
                },
                tempDir,
                () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        Finding noCve = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> enriched = pipeline.enrich(List.of(noCve));

        assertThat(enriched.get(0).epss()).isNull();
        assertThat(enriched.get(0).kev()).isFalse();
        assertThat(enriched.get(0).blastRadius()).isNotNull();
    }

    @Test
    void doesNotMutateInputAndPreservesOrder() {
        EpssClient epssClient = new EpssClient(uri -> EPSS_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        Finding original = findingWithCve("f1", "CVE-2021-44228");
        List<Finding> enriched = pipeline.enrich(List.of(original));

        assertThat(original.epss()).isNull(); // input untouched
        assertThat(enriched).hasSize(1);
        assertThat(enriched.get(0).id()).isEqualTo("f1");
    }
}
