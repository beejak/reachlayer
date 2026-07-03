package dev.reachlayer.connectors.fortify;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.spi.ScanSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FortifyConnectorTest {

    @TempDir Path tempDir;

    private byte[] fixtureBytes() throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("audit.fvdl")) {
            assertThat(in).isNotNull();
            return in.readAllBytes();
        }
    }

    @Test
    void supportsFvdlAndFprExtensionsOnly() throws IOException {
        FortifyConnector connector = new FortifyConnector();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("audit.fvdl")))).isTrue();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("scan.fpr")))).isTrue();
        assertThat(connector.supports(ScanSource.ofPath(Path.of("scan.json")))).isFalse();
    }

    @Test
    void ingestsFindingsFromRawFvdl() throws Exception {
        Path fvdl = tempDir.resolve("audit.fvdl");
        Files.write(fvdl, fixtureBytes());

        FortifyConnector connector = new FortifyConnector();
        List<Finding> findings = connector.ingest(ScanSource.ofPath(fvdl));

        assertThat(findings).hasSize(2);
        Finding sqli = findings.get(0);
        assertThat(sqli.source()).isEqualTo("fortify");
        assertThat(sqli.kind()).isEqualTo(FindingKind.SAST);
        assertThat(sqli.cwe()).containsExactly("CWE-89");
        assertThat(sqli.severity()).isEqualTo("4.0");
        assertThat(sqli.location().file()).endsWith("UserController.java");
        assertThat(sqli.location().startLine()).isEqualTo(42);
        assertThat(sqli.title()).isEqualTo("SQL Injection (Poor Style)");
        assertThat(sqli.description()).contains("SQL Injection");
        assertThat(sqli.cve()).isEmpty();
        assertThat(sqli.cvss().isKnown()).isFalse();
    }

    @Test
    void ingestsFindingsFromFprZipByExtractingAuditFvdl() throws Exception {
        Path fpr = tempDir.resolve("scan.fpr");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(fpr))) {
            zos.putNextEntry(new ZipEntry("audit.fvdl"));
            zos.write(fixtureBytes());
            zos.closeEntry();
            // Real FPRs also contain other artifacts we deliberately ignore.
            zos.putNextEntry(new ZipEntry("src-archive/README.txt"));
            zos.write("not analyzed".getBytes());
            zos.closeEntry();
        }

        FortifyConnector connector = new FortifyConnector();
        List<Finding> findings = connector.ingest(ScanSource.ofPath(fpr));

        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.source().equals("fortify"));
    }
}
