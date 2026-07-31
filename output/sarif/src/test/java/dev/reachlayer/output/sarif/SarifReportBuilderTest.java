package dev.reachlayer.output.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.model.RiskExplanation;
import dev.reachlayer.core.model.FixSuggestion;
import java.util.List;
import org.junit.jupiter.api.Test;

class SarifReportBuilderTest {

    // Mirrors SarifOutputRenderer's own mapper config, so tests verify the same null-omitting
    // serialization that production actually produces (a bare ObjectMapper would serialize
    // omitted fields like `region` as explicit JSON nulls instead of leaving them absent).
    private static final ObjectMapper MAPPER = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private static JsonNode toJson(SarifModel.SarifLog log) throws Exception {
        return MAPPER.readTree(MAPPER.writeValueAsString(log));
    }

    @Test
    void mapsFullyPopulatedSastFindingToRuleAndResult() throws Exception {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .cwe(List.of("CWE-89"))
                .title("SQL Injection")
                .description("Untrusted input flows into a SQL query.")
                .location(new Location("src/main/java/App.java", 42, 44, "App#handle"))
                .severity("High")
                .cvss(new Cvss(9.1, "CVSS:3.1/..."))
                .reachability(Reachability.REACHABLE)
                .reachEvidence("main -> App#handle -> Dao#query")
                .riskScore(92.0)
                .riskExplanation(RiskExplanation.builder().add("base", "0.9").add("reachable", "1.0").build())
                .fixSuggestion(FixSuggestion.template(FixSuggestion.Type.CODE_FIX, "Use a parameterized query."))
                .build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)));

        assertThat(json.at("/version").asText()).isEqualTo("2.1.0");
        assertThat(json.at("/$schema").asText()).contains("sarif-schema-2.1.0.json");
        assertThat(json.at("/runs/0/tool/driver/name").asText()).isEqualTo("Reachlayer");
        assertThat(json.at("/runs/0/tool/driver/rules").size()).isEqualTo(1);
        assertThat(json.at("/runs/0/tool/driver/rules/0/id").asText()).isEqualTo("fortify:CWE-89");

        JsonNode result = json.at("/runs/0/results/0");
        assertThat(result.at("/ruleId").asText()).isEqualTo("fortify:CWE-89");
        assertThat(result.at("/ruleIndex").asInt()).isEqualTo(0);
        assertThat(result.at("/level").asText()).isEqualTo("error"); // riskScore 92 >= 75
        assertThat(result.at("/message/text").asText())
                .contains("92.0/100")
                .contains("reachable")
                .contains("Use a parameterized query.");
        assertThat(result.at("/locations/0/physicalLocation/artifactLocation/uri").asText())
                .isEqualTo("src/main/java/App.java");
        assertThat(result.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(42);
        assertThat(result.at("/locations/0/physicalLocation/region/endLine").asInt()).isEqualTo(44);
        assertThat(result.at("/partialFingerprints/reachlayerFindingId~1v1").asText()).isEqualTo("f1");
    }

    @Test
    void scaFindingWithNoLocationGetsSyntheticDependencyLocationAndFlag() throws Exception {
        Finding finding = Finding.builder()
                .id("f2")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .cve(List.of("CVE-2021-44228"))
                .component(Component.of("org.apache.logging.log4j:log4j-core", "2.14.1"))
                .title("Remote code execution in Log4j")
                .build();

        JsonNode result = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)))
                .at("/runs/0/results/0");

        String uri = result.at("/locations/0/physicalLocation/artifactLocation/uri").asText();
        assertThat(uri).startsWith("dependencies/").contains("log4j-core@2.14.1");
        assertThat(result.at("/properties/reachlayerSyntheticLocation").asBoolean()).isTrue();
        assertThat(result.at("/locations/0/physicalLocation/region").isMissingNode()).isTrue();
    }

    @Test
    void findingWithNoCweOrCveFallsBackToSlugifiedTitleForRuleId() throws Exception {
        Finding finding = Finding.builder()
                .id("f3")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Hardcoded Password!!")
                .build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo("fortify:hardcoded-password");
    }

    @Test
    void distinctFindingsSharingTheSameCweShareOneRuleButProduceTwoResults() throws Exception {
        Finding f1 = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST)
                .cwe(List.of("CWE-89")).title("SQLi A").build();
        Finding f2 = Finding.builder().id("f2").source("fortify").kind(FindingKind.SAST)
                .cwe(List.of("CWE-89")).title("SQLi B").build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(f1, f2), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/tool/driver/rules").size()).isEqualTo(1);
        assertThat(json.at("/runs/0/results").size()).isEqualTo(2);
        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo(json.at("/runs/0/results/1/ruleId").asText());
        assertThat(json.at("/runs/0/results/0/ruleIndex").asInt()).isEqualTo(0);
        assertThat(json.at("/runs/0/results/1/ruleIndex").asInt()).isEqualTo(0);
    }

    @Test
    void neverThrowsOnSparselyPopulatedFinding() {
        Finding bare = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();
        RankedReport report = RankedReport.of(List.of(bare), "acme/widgets", 5);

        assertThatCode(() -> SarifReportBuilder.build(report)).doesNotThrowAnyException();
    }

    @Test
    void sparselyPopulatedFindingMessageDegradesGracefully() throws Exception {
        Finding bare = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        JsonNode result = toJson(SarifReportBuilder.build(RankedReport.of(List.of(bare), "acme/widgets", 5)))
                .at("/runs/0/results/0");

        assertThat(result.at("/message/text").asText())
                .contains("not scored")
                .contains("no fix suggestion available");
        assertThat(result.at("/level").asText()).isEqualTo("note"); // unknown severity, no riskScore -> conservative default
    }

    @Test
    void levelMappingBucketsRiskScoreIntoErrorWarningNote() throws Exception {
        Finding high = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).riskScore(80.0).build();
        Finding mid = Finding.builder().id("f2").source("fortify").kind(FindingKind.SAST).riskScore(50.0).build();
        Finding low = Finding.builder().id("f3").source("fortify").kind(FindingKind.SAST).riskScore(10.0).build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(high, mid, low), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/results/0/level").asText()).isEqualTo("error");
        assertThat(json.at("/runs/0/results/1/level").asText()).isEqualTo("warning");
        assertThat(json.at("/runs/0/results/2/level").asText()).isEqualTo("note");
    }
}
