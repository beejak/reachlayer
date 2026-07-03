package dev.reachlayer.connectors.fortify;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import org.junit.jupiter.api.Test;

class FvdlParserTest {

    @Test
    void parsesVulnerabilitiesAndDescriptions() throws Exception {
        FvdlParser parser = new FvdlParser();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("audit.fvdl")) {
            assertThat(in).as("audit.fvdl fixture on test classpath").isNotNull();
            FvdlDocument document = parser.parse(in);

            assertThat(document.vulnerabilities()).hasSize(2);

            RawVulnerability sqli = document.vulnerabilities().get(0);
            assertThat(sqli.classId()).isEqualTo("SQLI-0001-CLASS");
            assertThat(sqli.type()).isEqualTo("SQL Injection");
            assertThat(sqli.cwe()).isEqualTo("89");
            assertThat(sqli.instanceSeverity()).isEqualTo(4.0);
            assertThat(sqli.sourcePath()).endsWith("UserController.java");
            assertThat(sqli.sourceLine()).isEqualTo(42);

            RawVulnerability pathTraversal = document.vulnerabilities().get(1);
            assertThat(pathTraversal.type()).isEqualTo("Path Manipulation");
            assertThat(pathTraversal.cwe()).isEqualTo("22");

            assertThat(document.abstractsByClassId())
                    .containsEntry("SQLI-0001-CLASS", "Untrusted input is concatenated into a SQL statement, enabling SQL Injection.")
                    .containsKey("PATHTR-0002-CLASS");
        }
    }
}
