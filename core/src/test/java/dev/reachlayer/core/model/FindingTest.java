package dev.reachlayer.core.model;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class FindingTest {

    @Test
    void buildsWithDefaults() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .build();

        assertThat(finding.reachability()).isEqualTo(Reachability.UNKNOWN);
        assertThat(finding.reachEvidence()).isEqualTo("not analyzed");
        assertThat(finding.blastRadius()).isEqualTo(BlastRadius.NONE);
        assertThat(finding.cvss()).isEqualTo(Cvss.UNKNOWN);
        assertThat(finding.location()).isEqualTo(Location.unknown());
        assertThat(finding.severity()).isEqualTo("unknown");
        assertThat(finding.riskScore()).isNull();
    }

    @Test
    void toBuilderPreservesEarlierStagesWhileEnrichingLater() {
        Finding ingested = Finding.builder()
                .id("f2")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .cve(List.of("CVE-2021-1234"))
                .component(Component.of("org.example:lib", "1.0.0"))
                .severity("High")
                .build();

        Finding tagged = ingested.toBuilder()
                .reachability(Reachability.REACHABLE)
                .reachEvidence("main -> Controller.handle -> lib.Vulnerable.exec")
                .build();

        assertThat(tagged.id()).isEqualTo(ingested.id());
        assertThat(tagged.severity()).isEqualTo("High");
        assertThat(tagged.reachability()).isEqualTo(Reachability.REACHABLE);
        assertThat(ingested.reachability()).isEqualTo(Reachability.UNKNOWN); // original untouched
    }

    @Test
    void stableIdIsDeterministic() {
        Location loc = new Location("Foo.java", 10, 12, "Foo.bar()");
        Component comp = Component.of("org.example:lib", "1.0.0");

        String id1 = Finding.stableId("fortify", "XSS", loc, comp);
        String id2 = Finding.stableId("fortify", "XSS", loc, comp);

        assertThat(id1).isEqualTo(id2);
        assertThat(id1).startsWith("fortify-");
    }
}
