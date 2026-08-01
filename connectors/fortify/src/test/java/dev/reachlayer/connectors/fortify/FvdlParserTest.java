package dev.reachlayer.connectors.fortify;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.Test;

class FvdlParserTest {

    private static InputStream xml(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

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

    @Test
    void handlesEmptyFvdlWithNoVulnerabilities() throws Exception {
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities/>
                </FVDL>
                """;

        FvdlDocument document = new FvdlParser().parse(xml(fvdl));

        assertThat(document.vulnerabilities()).isEmpty();
        assertThat(document.abstractsByClassId()).isEmpty();
    }

    @Test
    void handlesVulnerabilityWithNoSourceLocationAndNoCwe() throws Exception {
        // Real Fortify output includes semantic/configuration findings with no source trace at
        // all (e.g. a weak-crypto config check) and findings whose analyzer never assigns a CWE.
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities>
                    <Vulnerability>
                      <ClassInfo>
                        <ClassID>WEAKCRYPTO-CLASS</ClassID>
                        <Type>Insecure Randomness</Type>
                        <Subtype></Subtype>
                        <AnalyzerName>configuration</AnalyzerName>
                        <DefaultSeverity>2.0</DefaultSeverity>
                      </ClassInfo>
                      <InstanceInfo>
                        <InstanceID>WEAKCRYPTO-INSTANCE</InstanceID>
                        <InstanceSeverity>2.0</InstanceSeverity>
                      </InstanceInfo>
                    </Vulnerability>
                  </Vulnerabilities>
                </FVDL>
                """;

        FvdlDocument document = new FvdlParser().parse(xml(fvdl));

        assertThat(document.vulnerabilities()).hasSize(1);
        RawVulnerability v = document.vulnerabilities().get(0);
        assertThat(v.cwe()).isNull();
        assertThat(v.sourcePath()).isNull();
        assertThat(v.sourceLine()).isNull();
    }

    @Test
    void twoInstancesSharingOneClassIdBothResolveTheSharedAbstract() throws Exception {
        // The common real-world case: the same vulnerability class (e.g. one SQL Injection rule)
        // fires at many call sites, each a distinct InstanceID under one shared ClassID/Abstract.
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities>
                    <Vulnerability>
                      <ClassInfo><ClassID>SHARED-CLASS</ClassID><Type>SQL Injection</Type><CWE>89</CWE></ClassInfo>
                      <InstanceInfo><InstanceID>INST-A</InstanceID><InstanceSeverity>4.0</InstanceSeverity></InstanceInfo>
                    </Vulnerability>
                    <Vulnerability>
                      <ClassInfo><ClassID>SHARED-CLASS</ClassID><Type>SQL Injection</Type><CWE>89</CWE></ClassInfo>
                      <InstanceInfo><InstanceID>INST-B</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
                    </Vulnerability>
                  </Vulnerabilities>
                  <Description classID="SHARED-CLASS">
                    <Abstract>Shared SQL Injection description.</Abstract>
                  </Description>
                </FVDL>
                """;

        FvdlDocument document = new FvdlParser().parse(xml(fvdl));

        assertThat(document.vulnerabilities()).hasSize(2);
        assertThat(document.abstractsByClassId()).containsEntry("SHARED-CLASS", "Shared SQL Injection description.");
        assertThat(document.vulnerabilities()).allMatch(v -> v.classId().equals("SHARED-CLASS"));
    }

    @Test
    void nonNumericSeverityAndConfidenceParseToNullRatherThanThrowing() throws Exception {
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities>
                    <Vulnerability>
                      <ClassInfo><ClassID>C1</ClassID><Type>Foo</Type><DefaultSeverity>N/A</DefaultSeverity></ClassInfo>
                      <InstanceInfo><InstanceID>I1</InstanceID><Confidence>unscored</Confidence></InstanceInfo>
                    </Vulnerability>
                  </Vulnerabilities>
                </FVDL>
                """;

        RawVulnerability v = new FvdlParser().parse(xml(fvdl)).vulnerabilities().get(0);

        assertThat(v.defaultSeverity()).isNull();
        assertThat(v.confidence()).isNull();
    }

    @Test
    void decodesXmlEntitiesAndUnicodeInAbstractText() throws Exception {
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities>
                    <Vulnerability>
                      <ClassInfo><ClassID>C1</ClassID><Type>Foo</Type></ClassInfo>
                      <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
                    </Vulnerability>
                  </Vulnerabilities>
                  <Description classID="C1">
                    <Abstract>Comparison uses &lt;script&gt; &amp; caf&#233; na&#239;ve unicode: éèç</Abstract>
                  </Description>
                </FVDL>
                """;

        FvdlDocument document = new FvdlParser().parse(xml(fvdl));

        assertThat(document.abstractsByClassId().get("C1"))
                .isEqualTo("Comparison uses <script> & café naïve unicode: éèç");
    }

    @Test
    void externalEntityInDoctypeIsRejectedNotResolved() {
        // XXE hardening (FvdlParser disables DTD/external-entity support). A malicious or
        // corrupted export attempting to read a local file via an external entity must fail
        // the parse, never silently substitute file contents into the resulting document.
        String fvdl = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE FVDL [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <FVDL xmlns="xmlns://www.fortify.com/schema/fvdl" version="1.0">
                  <Vulnerabilities>
                    <Vulnerability>
                      <ClassInfo><ClassID>C1</ClassID><Type>&xxe;</Type></ClassInfo>
                      <InstanceInfo><InstanceID>I1</InstanceID></InstanceInfo>
                    </Vulnerability>
                  </Vulnerabilities>
                </FVDL>
                """;

        assertThatThrownBy(() -> new FvdlParser().parse(xml(fvdl))).isInstanceOf(XMLStreamException.class);
    }
}
