package dev.reachlayer.reach;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent;
import dev.reachlayer.reach.signatures.ComponentLevelSignatureSource;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * End-to-end validation against the {@code fixtures:vulnerable-spring-app} module's real compiled
 * bytecode (PLAN.md §10 step 4 and step 8): resolves the on-disk classes directory Gradle put on
 * this module's test classpath via {@link Class#getProtectionDomain()}, points {@link
 * ReachabilityTagger} at it, and asserts the reachable-vs-unreachable outcome comes from a genuine
 * call-graph result rather than the {@code UNKNOWN} fallback path.
 *
 * <p>This deliberately asserts real {@code REACHABLE}/{@code UNREACHABLE} outcomes rather than
 * merely tolerating {@code UNKNOWN} — that is the actual point of the fixture (PLAN.md §10 step
 * 8). If SootUp behaves unexpectedly in some environment, {@link ReachabilityTagger} itself still
 * degrades gracefully to {@code UNKNOWN} for real pipeline runs (see {@link
 * ReachabilityTaggerTest#degradesAllFindingsToUnknownWhenCallGraphConstructionFails}); this test
 * failing would mean that graceful-degradation path is quietly swallowing a real regression here,
 * which is worth seeing rather than hiding.
 */
class ReachabilityTaggerFixtureIT {

    private Path fixtureClassesRoot() throws URISyntaxException {
        return Paths.get(
                ReachableVulnerableComponent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    @Test
    void tagsReachableAndUnreachableVulnerableComponentsFromRealCallGraph() throws Exception {
        Path classesRoot = fixtureClassesRoot();
        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        Finding reachableFinding = scaFinding("dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent");
        Finding unreachableFinding =
                scaFinding("dev.reachlayer.fixtures.vulnapp.UnreachableVulnerableComponent");

        List<Finding> tagged = tagger.tag(List.of(reachableFinding, unreachableFinding));
        Finding taggedReachable = tagged.get(0);
        Finding taggedUnreachable = tagged.get(1);

        assertThat(taggedReachable.reachability()).isEqualTo(Reachability.REACHABLE);
        assertThat(taggedReachable.reachEvidence()).contains("call graph");

        assertThat(taggedUnreachable.reachability()).isEqualTo(Reachability.UNREACHABLE);
        assertThat(taggedUnreachable.reachEvidence()).contains("no call path found");
    }

    @Test
    void notesDisagreementWithVendorReportedReachabilityWithoutOverridingOwnTag() throws Exception {
        Path classesRoot = fixtureClassesRoot();
        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        // Reachlayer's own call-graph analysis will tag this REACHABLE (see the test above); the
        // scanner claims UNREACHABLE. Neither signal should silently win -- both must survive.
        Finding disagreeing =
                scaFinding("dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent")
                        .toBuilder()
                        .vendorReachability(Reachability.UNREACHABLE)
                        .build();

        Finding tagged = tagger.tag(List.of(disagreeing)).get(0);

        assertThat(tagged.reachability()).isEqualTo(Reachability.REACHABLE);
        assertThat(tagged.vendorReachability()).isEqualTo(Reachability.UNREACHABLE);
        assertThat(tagged.reachEvidence()).contains("disagrees with vendor-reported reachability (unreachable)");
    }

    @Test
    void chaFailsToResolveCallEdgesThroughALambdaDispatchAConfirmedFalseNegative() throws Exception {
        // This reproduces, for real, the invokedynamic/lambda gap that docs/reachability-caveats.md
        // previously only cited from an unverified secondary source
        // (docs/competitive-landscape-commercial-technical.md). LambdaVulnerableComponent.unsafeMethod()
        // genuinely IS reachable at runtime -- LambdaDispatchController.reachViaLambda() is a real
        // Spring MVC entry point that calls it through a java.util.function.Supplier lambda -- but
        // SootUp 1.1.2's ClassHierarchyAnalysisAlgorithm has no invokedynamic/lambda-metafactory
        // resolution at all (confirmed by inspecting sootup.callgraph-1.1.2.jar's contents: no
        // lambda/invokedynamic-handling classes exist in it), so the call edge from
        // Supplier.get() to the lambda body is never added to the graph.
        //
        // This assertion intentionally documents the CURRENT (wrong, from a runtime-behavior
        // standpoint) tag as a known, reproduced limitation -- not because UNREACHABLE is correct
        // here, but so that a future SootUp upgrade or custom invokedynamic edge resolver that
        // fixes this will make this specific test start failing, which is exactly the signal
        // needed to know the fix worked and this comment/docs/reachability-caveats.md need updating.
        Path classesRoot = fixtureClassesRoot();
        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        Finding finding = scaFinding("dev.reachlayer.fixtures.vulnapp.LambdaVulnerableComponent");
        Finding tagged = tagger.tag(List.of(finding)).get(0);

        assertThat(tagged.reachability()).isEqualTo(Reachability.UNREACHABLE);
        assertThat(tagged.reachEvidence()).contains("no call path found");
    }

    @Test
    void tagsSastFindingWithComponentLessLocationAgainstTheSameCallGraph() throws Exception {
        Path classesRoot = fixtureClassesRoot();
        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        Finding sastFinding =
                Finding.builder()
                        .id("sast-1")
                        .source("fortify")
                        .kind(FindingKind.SAST)
                        .location(
                                Location.ofFile(
                                        "src/main/java/dev/reachlayer/fixtures/vulnapp/ReachableVulnerableComponent.java"))
                        .build();

        List<Finding> tagged = tagger.tag(List.of(sastFinding));

        assertThat(tagged.get(0).reachability()).isEqualTo(Reachability.REACHABLE);
    }

    private static Finding scaFinding(String componentName) {
        return Finding.builder()
                .id("sca-" + componentName)
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(Component.of(componentName, "1.0.0"))
                .location(Location.unknown())
                .build();
    }
}
