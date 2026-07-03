package dev.reachlayer.connectors.blackduck;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.spi.ScanSource;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;

class BlackDuckConnectorTest {

    private Path fixture() throws URISyntaxException {
        return Paths.get(getClass().getClassLoader().getResource("scan.json").toURI());
    }

    @Test
    void supportsJsonAndBdioExtensions() {
        BlackDuckConnector connector = new BlackDuckConnector();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("scan.json")))).isTrue();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("scan.bdio")))).isTrue();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("audit.fvdl")))).isFalse();
    }

    @Test
    void ingestsOneFindingPerComponentVulnerability() throws Exception {
        BlackDuckConnector connector = new BlackDuckConnector();
        List<Finding> findings = connector.ingest(ScanSource.ofPath(fixture()));

        assertThat(findings).hasSize(3);
        assertThat(findings).allMatch(f -> f.source().equals("blackduck"));
        assertThat(findings).allMatch(f -> f.kind() == FindingKind.SCA);

        Finding log4shell = findings.stream()
                .filter(f -> f.cve().contains("CVE-2021-44228"))
                .findFirst()
                .orElseThrow();
        assertThat(log4shell.component().name()).isEqualTo("log4j-core");
        assertThat(log4shell.component().version()).isEqualTo("2.14.1");
        assertThat(log4shell.cwe()).containsExactly("CWE-502");
        assertThat(log4shell.severity()).isEqualTo("CRITICAL");
        assertThat(log4shell.cvss().score()).isEqualTo(10.0);
        assertThat(log4shell.cvss().vector()).contains("CVSS:3.1");
        assertThat(log4shell.description()).contains("Log4Shell");
    }
}
