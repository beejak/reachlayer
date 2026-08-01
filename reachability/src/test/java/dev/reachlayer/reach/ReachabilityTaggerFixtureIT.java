package dev.reachlayer.reach;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.config.EntryPointOverrides;
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
    void resolvesCallEdgesThroughALambdaDispatchNowThatTheGapIsFixed() throws Exception {
        // This is a fixed version of a previously-confirmed, reproduced bug: SootUp 1.1.2's
        // ClassHierarchyAnalysisAlgorithm.resolveCall deliberately returns no call targets for ANY
        // invokedynamic call site (verified by decompiling sootup.callgraph-1.1.2.jar), which used
        // to leave LambdaVulnerableComponent.unsafeMethod() tagged UNREACHABLE even though
        // LambdaDispatchController.reachViaLambda() -- a real Spring MVC entry point -- calls it
        // directly through a java.util.function.Supplier lambda. CallGraphBuilder now uses
        // LambdaAwareChaAlgorithm (see that class's Javadoc), which resolves a LambdaMetafactory
        // -bootstrapped invokedynamic site to its real implementation method via the bootstrap
        // MethodHandle SootUp's own bytecode frontend already parses out -- no custom bytecode
        // parsing needed here, just overriding the one case the stock algorithm special-cases away.
        //
        // This test previously asserted the old, wrong (from a runtime-behavior standpoint)
        // UNREACHABLE tag on purpose, specifically so that a fix landing would flip this
        // assertion and force this test (and docs/reachability-caveats.md) to be updated --
        // exactly what happened here.
        Path classesRoot = fixtureClassesRoot();
        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        Finding finding = scaFinding("dev.reachlayer.fixtures.vulnapp.LambdaVulnerableComponent");
        Finding tagged = tagger.tag(List.of(finding)).get(0);

        assertThat(tagged.reachability()).isEqualTo(Reachability.REACHABLE);
        assertThat(tagged.reachEvidence()).contains("call graph");
    }

    @Test
    void nonLambdaInvokedynamicCallSitesDoNotCrashCallGraphConstruction() throws Exception {
        // StringConcatController.concat() compiles to an invokedynamic call site bootstrapped via
        // java.lang.invoke.StringConcatFactory (javac's default string-concatenation strategy
        // since Java 9), not java.lang.invoke.LambdaMetafactory. LambdaAwareChaAlgorithm must not
        // assume every invokedynamic site is a lambda -- this asserts call graph construction
        // (which discovers and seeds from this entry point automatically, since it's a real
        // @GetMapping handler) succeeds cleanly rather than throwing or mis-resolving.
        Path classesRoot = fixtureClassesRoot();

        ReachabilityTagger tagger = new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());

        // A call graph was successfully constructed at all (not degraded to UNKNOWN because
        // construction failed) -- reusing an already-known-reachable finding as the probe.
        Finding reachableFinding = scaFinding("dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent");
        Finding tagged = tagger.tag(List.of(reachableFinding)).get(0);
        assertThat(tagged.reachability()).isEqualTo(Reachability.REACHABLE);
    }

    @Test
    void configuredExtraClassesOverrideFlipsAnUnrecognizedEntryPointFromUnreachableToReachable() throws Exception {
        Path classesRoot = fixtureClassesRoot();
        Finding finding =
                scaFinding("dev.reachlayer.fixtures.vulnapp.EntryPointOverrideVulnerableComponent");

        ReachabilityTagger withoutOverrides =
                new ReachabilityTagger(classesRoot, new ComponentLevelSignatureSource());
        Finding taggedWithoutOverrides = withoutOverrides.tag(List.of(finding)).get(0);
        assertThat(taggedWithoutOverrides.reachability()).isEqualTo(Reachability.UNREACHABLE);

        ReachabilityTagger withOverrides =
                new ReachabilityTagger(
                        classesRoot,
                        List.of(new ComponentLevelSignatureSource()),
                        new EntryPointOverrides(
                                List.of(), List.of("dev.reachlayer.fixtures.vulnapp.NightlyReportJob")));
        Finding taggedWithOverrides = withOverrides.tag(List.of(finding)).get(0);
        assertThat(taggedWithOverrides.reachability()).isEqualTo(Reachability.REACHABLE);
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
