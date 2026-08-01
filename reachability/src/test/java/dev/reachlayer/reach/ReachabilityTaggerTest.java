package dev.reachlayer.reach;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.reach.signatures.ComponentLevelSignatureSource;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReachabilityTaggerTest {

    @Test
    void classNameFromSourcePathStripsStandardSourceRoots() {
        assertThat(
                        ReachabilityTagger.classNameFromSourcePath(
                                "src/main/java/dev/reachlayer/fixtures/vulnapp/UserController.java"))
                .isEqualTo("dev.reachlayer.fixtures.vulnapp.UserController");
    }

    @Test
    void classNameFromSourcePathHandlesWindowsStyleSeparators() {
        assertThat(ReachabilityTagger.classNameFromSourcePath("src\\main\\java\\dev\\reachlayer\\Foo.java"))
                .isEqualTo("dev.reachlayer.Foo");
    }

    @Test
    void classNameFromSourcePathHandlesPathsWithoutARecognizedSourceRoot() {
        // No src/main/java marker, but still a .java file: best-effort, use the whole path.
        assertThat(ReachabilityTagger.classNameFromSourcePath("dev/reachlayer/Foo.java"))
                .isEqualTo("dev.reachlayer.Foo");
    }

    @Test
    void classNameFromSourcePathReturnsNullForNonJavaOrMissingPaths() {
        assertThat(ReachabilityTagger.classNameFromSourcePath("some/config.yml")).isNull();
        assertThat(ReachabilityTagger.classNameFromSourcePath(null)).isNull();
        assertThat(ReachabilityTagger.classNameFromSourcePath("")).isNull();
        assertThat(ReachabilityTagger.classNameFromSourcePath("   ")).isNull();
    }

    @Test
    void degradesAllFindingsToUnknownWhenCallGraphConstructionFails() {
        ReachabilityTagger tagger =
                new ReachabilityTagger(Path.of("this/path/does/not/exist"), new ComponentLevelSignatureSource());

        Finding scaFinding =
                Finding.builder()
                        .id("f1")
                        .source("blackduck")
                        .kind(FindingKind.SCA)
                        .component(Component.of("some-lib", "1.0"))
                        .location(Location.unknown())
                        .build();
        Finding sastFinding =
                Finding.builder()
                        .id("f2")
                        .source("fortify")
                        .kind(FindingKind.SAST)
                        .location(Location.ofFile("src/main/java/dev/reachlayer/Foo.java"))
                        .build();

        List<Finding> tagged = tagger.tag(List.of(scaFinding, sastFinding));

        assertThat(tagged).hasSize(2);
        assertThat(tagged).allMatch(f -> f.reachability() == Reachability.UNKNOWN);
        assertThat(tagged).allMatch(f -> f.reachEvidence().startsWith("reachability analysis unavailable:"));
    }

    @Test
    void notesVendorReachabilityAsInconclusiveRatherThanDisagreementWhenOwnAnalysisIsUnavailable() {
        ReachabilityTagger tagger =
                new ReachabilityTagger(Path.of("this/path/does/not/exist"), new ComponentLevelSignatureSource());
        Finding scaFinding =
                Finding.builder()
                        .id("f1")
                        .source("blackduck")
                        .kind(FindingKind.SCA)
                        .component(Component.of("some-lib", "1.0"))
                        .location(Location.unknown())
                        .vendorReachability(Reachability.REACHABLE)
                        .build();

        Finding tagged = tagger.tag(List.of(scaFinding)).get(0);

        assertThat(tagged.reachability()).isEqualTo(Reachability.UNKNOWN);
        assertThat(tagged.vendorReachability()).isEqualTo(Reachability.REACHABLE);
        assertThat(tagged.reachEvidence())
                .contains("vendor-reported reachability (reachable) noted, Reachlayer's own analysis was inconclusive");
    }

    @Test
    void neverMutatesInputFindings() {
        ReachabilityTagger tagger =
                new ReachabilityTagger(Path.of("this/path/does/not/exist"), new ComponentLevelSignatureSource());
        Finding original =
                Finding.builder()
                        .id("f1")
                        .source("blackduck")
                        .kind(FindingKind.SCA)
                        .component(Component.of("some-lib", "1.0"))
                        .build();

        tagger.tag(List.of(original));

        assertThat(original.reachability()).isEqualTo(Reachability.UNKNOWN);
        assertThat(original.reachEvidence()).isEqualTo("not analyzed");
    }
}
