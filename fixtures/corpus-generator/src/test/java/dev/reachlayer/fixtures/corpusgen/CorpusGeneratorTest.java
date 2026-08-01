package dev.reachlayer.fixtures.corpusgen;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.connectors.blackduck.BlackDuckConnector;
import dev.reachlayer.connectors.fortify.FortifyConnector;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.spi.ScanSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CorpusGeneratorTest {

    @Test
    void sameSeedProducesIdenticalOutput() {
        GeneratedCorpus a = CorpusGenerator.generate(42L, 40, 60);
        GeneratedCorpus b = CorpusGenerator.generate(42L, 40, 60);

        assertThat(a.fvdlXml()).isEqualTo(b.fvdlXml());
        assertThat(a.blackDuckJson()).isEqualTo(b.blackDuckJson());
    }

    @Test
    void differentSeedProducesDifferentOutput() {
        GeneratedCorpus a = CorpusGenerator.generate(1L, 10, 10);
        GeneratedCorpus b = CorpusGenerator.generate(2L, 10, 10);

        assertThat(a.blackDuckJson()).isNotEqualTo(b.blackDuckJson());
    }

    @Test
    void findingCountsMatchRequestedPlusAnchors() {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);

        assertThat(corpus.sastFindingCount()).isEqualTo(43); // 3 anchors + 40
        assertThat(corpus.scaFindingCount()).isEqualTo(62); // 2 anchors + 60
    }

    @Test
    void zeroExtraCountsStillProducesOnlyTheAnchors() {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 0, 0);

        assertThat(corpus.sastFindingCount()).isEqualTo(3);
        assertThat(corpus.scaFindingCount()).isEqualTo(2);
    }

    @Test
    void generatedFvdlParsesViaTheRealFortifyConnectorWithExpectedCount(@TempDir Path tempDir) throws Exception {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);
        Path fvdl = tempDir.resolve("audit.fvdl");
        Files.writeString(fvdl, corpus.fvdlXml());

        List<Finding> findings = new FortifyConnector().ingest(ScanSource.ofPath(fvdl));

        assertThat(findings).hasSize(corpus.sastFindingCount());
    }

    @Test
    void generatedFvdlIncludesTheThreeRealFixtureClassAnchors() {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);

        assertThat(corpus.fvdlXml()).contains("ReachableVulnerableComponent.java");
        assertThat(corpus.fvdlXml()).contains("UnreachableVulnerableComponent.java");
        assertThat(corpus.fvdlXml()).contains("VulnerableController.java");
    }

    @Test
    void generatedBlackDuckJsonParsesViaTheRealConnectorWithExpectedCount(@TempDir Path tempDir) throws Exception {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);
        Path scan = tempDir.resolve("scan.json");
        Files.writeString(scan, corpus.blackDuckJson());

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(scan));

        assertThat(findings).hasSize(corpus.scaFindingCount());
    }

    @Test
    void generatedBlackDuckJsonIncludesTheTwoRealFixtureClassAnchorComponents() {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 40, 60);

        assertThat(corpus.blackDuckJson())
                .contains("dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent")
                .contains("dev.reachlayer.fixtures.vulnapp.UnreachableVulnerableComponent");
    }

    @Test
    void bulkScaFindingsBeyondTheRealCvePoolGetDistinctSyntheticCves(@TempDir Path tempDir) throws Exception {
        GeneratedCorpus corpus = CorpusGenerator.generate(42L, 0, 10);
        Path scan = tempDir.resolve("scan.json");
        Files.writeString(scan, corpus.blackDuckJson());

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(scan));

        assertThat(findings).extracting(f -> f.id()).doesNotHaveDuplicates();
    }
}
