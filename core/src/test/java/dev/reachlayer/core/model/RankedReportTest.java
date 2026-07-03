package dev.reachlayer.core.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class RankedReportTest {

    private Finding finding(String id, double score) {
        return Finding.builder()
                .id(id)
                .source("fortify")
                .kind(FindingKind.SAST)
                .riskScore(score)
                .build();
    }

    @Test
    void sortsDescendingByRiskScore() {
        RankedReport report = RankedReport.of(
                List.of(finding("low", 10), finding("high", 90), finding("mid", 50)), "acme/repo", 2);

        assertThat(report.findings()).extracting(Finding::id).containsExactly("high", "mid", "low");
        assertThat(report.top()).extracting(Finding::id).containsExactly("high", "mid");
        assertThat(report.rest()).extracting(Finding::id).containsExactly("low");
    }

    @Test
    void treatsMissingScoreAsZero() {
        Finding unscored = Finding.builder().id("u").source("blackduck").kind(FindingKind.SCA).build();
        RankedReport report = RankedReport.of(List.of(finding("scored", 5), unscored), "acme/repo", 5);

        assertThat(report.findings()).extracting(Finding::id).containsExactly("scored", "u");
    }
}
