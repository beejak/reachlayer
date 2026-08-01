package dev.reachlayer.output.api;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.model.RiskExplanation;
import java.util.List;
import org.junit.jupiter.api.Test;

class MarkdownReportFormatterTest {

    private static final String MARKER = "<!-- reachlayer:report -->";

    private final MarkdownReportFormatter formatter = new MarkdownReportFormatter();

    @Test
    void rendersMarkerHeadingAndSummary() {
        RankedReport report = RankedReport.of(List.of(fullyPopulatedFinding()), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).startsWith(MARKER);
        assertThat(markdown).contains("## Reachlayer risk triage — acme/widgets");
        assertThat(markdown).contains("1 finding analyzed, showing top 1");
    }

    @Test
    void topTableContainsFullyPopulatedFindingDetails() {
        RankedReport report = RankedReport.of(List.of(fullyPopulatedFinding()), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).contains("92.3");
        assertThat(markdown).contains("Critical");
        assertThat(markdown).contains("reachable");
        assertThat(markdown).contains("CVE-2021-44228");
        assertThat(markdown).contains("CWE-502");
        assertThat(markdown).contains("Deserialization of untrusted data");
        assertThat(markdown).contains("log4j-core@2.14.1");
        assertThat(markdown).contains("internet-facing");
        assertThat(markdown).contains("Upgrade to log4j-core");
    }

    @Test
    void reachabilityCellNotesVendorDisagreementButNotAgreement() {
        Finding disagreeing =
                fullyPopulatedFinding().toBuilder().vendorReachability(Reachability.UNREACHABLE).build();
        Finding agreeing =
                fullyPopulatedFinding().toBuilder()
                        .id("full-2")
                        .vendorReachability(Reachability.REACHABLE)
                        .build();

        String disagreeingMarkdown =
                formatter.format(RankedReport.of(List.of(disagreeing), "acme/widgets", 5), MARKER);
        String agreeingMarkdown = formatter.format(RankedReport.of(List.of(agreeing), "acme/widgets", 5), MARKER);

        assertThat(disagreeingMarkdown).contains("reachable (vendor: unreachable)");
        assertThat(agreeingMarkdown).doesNotContain("vendor:");
    }

    @Test
    void handlesSparseFindingWithoutThrowingAndUsesPlaceholders() {
        Finding sparse = Finding.builder()
                .id("sparse-1")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .build();

        RankedReport report = RankedReport.of(List.of(sparse), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).contains("n/a"); // riskScore null
        assertThat(markdown).contains("(untitled)"); // title null
        assertThat(markdown).contains("| - |"); // empty cve/cwe placeholder
        assertThat(markdown).contains("no suggestion available"); // fixSuggestion null
        assertThat(markdown).contains("not scored"); // riskExplanation null
        assertThat(markdown).contains("unknown"); // reachability defaults to UNKNOWN -> "unknown"
    }

    @Test
    void topFindingsAreVisibleWithoutExpandingDetailsAndRestAreCollapsed() {
        Finding top1 = findingWithScore("top-1", 90.0);
        Finding top2 = findingWithScore("top-2", 80.0);
        Finding rest1 = findingWithScore("rest-1", 10.0);

        RankedReport report = RankedReport.of(List.of(top1, top2, rest1), "acme/widgets", 2);

        String markdown = formatter.format(report, MARKER);

        int detailsIndex = markdown.indexOf("<details>");
        assertThat(detailsIndex).isGreaterThan(0);

        String beforeDetails = markdown.substring(0, detailsIndex);
        assertThat(beforeDetails).contains("top-1");
        assertThat(beforeDetails).contains("top-2");
        assertThat(beforeDetails).doesNotContain("rest-1");

        String afterDetails = markdown.substring(detailsIndex);
        assertThat(afterDetails).contains("rest-1");
        assertThat(afterDetails).contains("Show all 3 findings");
        assertThat(markdown).contains("</details>");
    }

    @Test
    void pipeAndNewlineCharactersInFreeTextDoNotCorruptTableStructure() {
        Finding malicious = Finding.builder()
                .id("malicious-1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Bad | pipe\nand a newline | too")
                .severity("High")
                .riskScore(50.0)
                .fixSuggestion(FixSuggestion.template(FixSuggestion.Type.CODE_FIX, "Fix | this\nplease"))
                .build();

        RankedReport report = RankedReport.of(List.of(malicious), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        String[] lines = markdown.split("\n");
        String headerLine = null;
        for (String line : lines) {
            if (line.startsWith("| Rank |")) {
                headerLine = line;
                break;
            }
        }
        assertThat(headerLine).isNotNull();
        int expectedDelimiters = countUnescapedPipes(headerLine);

        boolean foundDataRow = false;
        for (String line : lines) {
            if (line.startsWith("| 1 |")) {
                foundDataRow = true;
                assertThat(line).doesNotContain("\n");
                assertThat(countUnescapedPipes(line)).isEqualTo(expectedDelimiters);
            }
        }
        assertThat(foundDataRow).isTrue();
    }

    private static int countUnescapedPipes(String line) {
        String withoutEscapedPipes = line.replace("\\|", "");
        int count = 0;
        for (int i = 0; i < withoutEscapedPipes.length(); i++) {
            if (withoutEscapedPipes.charAt(i) == '|') {
                count++;
            }
        }
        return count;
    }

    private static Finding findingWithScore(String id, double score) {
        return Finding.builder()
                .id(id)
                .source("fortify")
                .kind(FindingKind.SAST)
                .title(id)
                .severity("Medium")
                .riskScore(score)
                .build();
    }

    private static Finding findingWithScoreAndIsNew(String id, double score, boolean isNew) {
        return Finding.builder()
                .id(id)
                .source("fortify")
                .kind(FindingKind.SAST)
                .title(id)
                .severity("Medium")
                .riskScore(score)
                .isNew(isNew)
                .build();
    }

    @Test
    void undiffedOutputContainsNoBaselineHeadingsWhenNoFindingHasIsNewSet() {
        RankedReport report = RankedReport.of(List.of(fullyPopulatedFinding()), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).doesNotContain("New findings introduced by this change");
        assertThat(markdown).doesNotContain("Pre-existing findings");
    }

    @Test
    void baselineModeShowsNewFindingsInPrimaryTableAndCollapsesPreExisting() {
        Finding newFinding = findingWithScoreAndIsNew("new-1", 90.0, true);
        Finding existingFinding = findingWithScoreAndIsNew("existing-1", 95.0, false);

        RankedReport report = RankedReport.of(List.of(newFinding, existingFinding), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).contains("2 findings analyzed against the baseline — 1 new, 1 pre-existing.");
        assertThat(markdown).contains("### New findings introduced by this change");
        assertThat(markdown).contains("### Pre-existing findings (unchanged from baseline)");

        int newHeadingIndex = markdown.indexOf("### New findings introduced by this change");
        int existingHeadingIndex = markdown.indexOf("### Pre-existing findings");
        String newSection = markdown.substring(newHeadingIndex, existingHeadingIndex);
        String existingSection = markdown.substring(existingHeadingIndex);

        assertThat(newSection).contains("new-1");
        assertThat(newSection).doesNotContain("existing-1");
        assertThat(existingSection).contains("existing-1");
        assertThat(existingSection).contains("Show 1 pre-existing finding</summary>");
    }

    @Test
    void baselineModeWithNoNewFindingsShowsReassuringMessageAndStillListsExisting() {
        Finding existingFinding = findingWithScoreAndIsNew("existing-1", 50.0, false);
        RankedReport report = RankedReport.of(List.of(existingFinding), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown)
                .contains("_No new findings introduced by this change compared to the baseline._");
        assertThat(markdown).contains("existing-1");
    }

    @Test
    void baselineModeOmitsPreExistingSectionEntirelyWhenEverythingIsNew() {
        Finding newFinding = findingWithScoreAndIsNew("new-1", 90.0, true);
        RankedReport report = RankedReport.of(List.of(newFinding), "acme/widgets", 5);

        String markdown = formatter.format(report, MARKER);

        assertThat(markdown).doesNotContain("Pre-existing findings");
    }

    @Test
    void baselineModeNewFindingsBeyondTopNAreCollapsedSeparatelyFromPreExisting() {
        Finding new1 = findingWithScoreAndIsNew("new-1", 90.0, true);
        Finding new2 = findingWithScoreAndIsNew("new-2", 80.0, true);
        Finding existing1 = findingWithScoreAndIsNew("existing-1", 70.0, false);

        RankedReport report = RankedReport.of(List.of(new1, new2, existing1), "acme/widgets", 1);

        String markdown = formatter.format(report, MARKER);

        int newHeadingIndex = markdown.indexOf("### New findings introduced by this change");
        int detailsIndex = markdown.indexOf("<details>", newHeadingIndex);
        int existingHeadingIndex = markdown.indexOf("### Pre-existing findings");

        String primaryNewSection = markdown.substring(newHeadingIndex, detailsIndex);
        assertThat(primaryNewSection).contains("new-1");
        assertThat(primaryNewSection).doesNotContain("new-2");

        String collapsedNewSection = markdown.substring(detailsIndex, existingHeadingIndex);
        assertThat(collapsedNewSection).contains("new-2");
        assertThat(collapsedNewSection).contains("Show all 2 new findings");

        assertThat(markdown.substring(existingHeadingIndex)).contains("existing-1");
    }

    private static Finding fullyPopulatedFinding() {
        return Finding.builder()
                .id("full-1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .cve(List.of("CVE-2021-44228"))
                .cwe(List.of("CWE-502"))
                .component(new Component("log4j-core", "2.14.1", "maven"))
                .location(new Location("src/main/java/App.java", 42, 45, "App.handle()"))
                .severity("Critical")
                .cvss(new Cvss(9.8, "CVSS:3.1/AV:N/AC:L"))
                .title("Deserialization of untrusted data")
                .description("JNDI lookup allows remote code execution")
                .reachability(Reachability.REACHABLE)
                .reachEvidence("main -> App.handle -> vulnerable sink")
                .epss(new Epss(0.97, 0.999, "2024-01-01"))
                .kev(true)
                .blastRadius(new BlastRadius(true, true, false, false, List.of("downstream-service")))
                .riskScore(92.3)
                .riskExplanation(RiskExplanation.builder()
                        .add("base", 0.9)
                        .add("exploit", 0.97)
                        .build())
                .fixSuggestion(FixSuggestion.llm(
                        FixSuggestion.Type.VERSION_BUMP,
                        "Upgrade to log4j-core 2.17.1 to resolve CVE-2021-44228.",
                        0.9))
                .build();
    }
}
