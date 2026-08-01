package dev.reachlayer.connectors.blackduck;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.ScanSource;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BlackDuckConnectorTest {

    @TempDir Path tempDir;

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

    private Path writeJson(String content) throws Exception {
        Path file = tempDir.resolve("scan.json");
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    @Test
    void componentWithEmptyVulnerabilitiesArrayProducesNoFindingsButDoesNotCrash() throws Exception {
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "clean-lib", "componentVersion": "1.0.0", "vulnerabilities": [] }
                  ]
                }
                """);

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(file));

        assertThat(findings).isEmpty();
    }

    @Test
    void componentWithNoVulnerabilitiesKeyAtAllProducesNoFindings() throws Exception {
        // Real Black Duck component-inventory output includes plenty of components with no
        // reported vulnerabilities at all, not even an empty array.
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "clean-lib", "componentVersion": "1.0.0" }
                  ]
                }
                """);

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(file));

        assertThat(findings).isEmpty();
    }

    @Test
    void rootWithNoComponentsKeyProducesEmptyFindingsNotACrash() throws Exception {
        Path file = writeJson("{ \"scanId\": \"empty-scan\" }");

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(file));

        assertThat(findings).isEmpty();
    }

    @Test
    void throwsConnectorExceptionOnEmptyFile() throws Exception {
        Path file = writeJson("");

        assertThatThrownBy(() -> new BlackDuckConnector().ingest(ScanSource.ofPath(file)))
                .isInstanceOf(ConnectorException.class)
                .hasMessageContaining("Empty Black Duck export");
    }

    @Test
    void throwsConnectorExceptionOnMalformedJson() throws Exception {
        Path file = writeJson("{ this is not valid json ");

        assertThatThrownBy(() -> new BlackDuckConnector().ingest(ScanSource.ofPath(file)))
                .isInstanceOf(ConnectorException.class)
                .hasMessageContaining("Failed to parse Black Duck export");
    }

    @Test
    void missingCvssScoreAndSeverityDegradeToUnknownRatherThanThrowing() throws Exception {
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "mystery-lib", "componentVersion": "0.1.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-00001" } ] }
                  ]
                }
                """);

        Finding f = new BlackDuckConnector().ingest(ScanSource.ofPath(file)).get(0);

        assertThat(f.cvss().score()).isNull();
        assertThat(f.cvss().isKnown()).isFalse();
        assertThat(f.severity()).isEqualTo("unknown");
    }

    @Test
    void findingWithNoCveIdStillProducesAFindingTitledByComponentCoordinate() throws Exception {
        // A component-level (e.g. license-risk) entry with no associated CVE.
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "some-lib", "componentVersion": "2.0.0",
                      "vulnerabilities": [ { "severity": "LOW" } ] }
                  ]
                }
                """);

        Finding f = new BlackDuckConnector().ingest(ScanSource.ofPath(file)).get(0);

        assertThat(f.cve()).isEmpty();
        assertThat(f.title()).isEqualTo("some-lib@2.0.0");
    }

    @Test
    void sameCveAcrossTwoDifferentComponentsProducesTwoDistinctFindings() throws Exception {
        // A shared transitive vulnerability affecting two different direct dependencies at
        // different versions must not collapse into one Finding — component identity matters.
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "lib-a", "componentVersion": "1.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-99999" } ] },
                    { "componentName": "lib-b", "componentVersion": "2.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-99999" } ] }
                  ]
                }
                """);

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(file));

        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(f -> f.id()).doesNotHaveDuplicates();
        assertThat(findings).allMatch(f -> f.cve().contains("CVE-2024-99999"));
    }

    @Test
    void parsesOptionalVendorReachabilityFieldCaseInsensitively() throws Exception {
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "lib-a", "componentVersion": "1.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-11111", "vendorReachability": "reachable" } ] },
                    { "componentName": "lib-b", "componentVersion": "2.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-22222", "vendorReachability": "UNREACHABLE" } ] }
                  ]
                }
                """);

        List<Finding> findings = new BlackDuckConnector().ingest(ScanSource.ofPath(file));

        assertThat(findings)
                .extracting(f -> f.vendorReachability())
                .containsExactlyInAnyOrder(Reachability.REACHABLE, Reachability.UNREACHABLE);
    }

    @Test
    void vendorReachabilityIsNullWhenFieldIsAbsent() throws Exception {
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "lib-a", "componentVersion": "1.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-33333" } ] }
                  ]
                }
                """);

        Finding f = new BlackDuckConnector().ingest(ScanSource.ofPath(file)).get(0);

        assertThat(f.vendorReachability()).isNull();
    }

    @Test
    void vendorReachabilityIsNullRatherThanThrowingWhenFieldHasAnUnrecognizedValue() throws Exception {
        Path file = writeJson(
                """
                {
                  "components": [
                    { "componentName": "lib-a", "componentVersion": "1.0.0",
                      "vulnerabilities": [ { "cveId": "CVE-2024-44444", "vendorReachability": "maybe-ish" } ] }
                  ]
                }
                """);

        Finding f = new BlackDuckConnector().ingest(ScanSource.ofPath(file)).get(0);

        assertThat(f.vendorReachability()).isNull();
    }
}
