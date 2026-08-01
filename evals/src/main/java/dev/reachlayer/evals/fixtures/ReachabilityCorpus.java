package dev.reachlayer.evals.fixtures;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * The labeled reachability corpus backing {@code ReachabilityAccuracyEvalTest} and {@link
 * dev.reachlayer.evals.EvalRunner}.
 *
 * <p>Reuses the real compiled bytecode of {@code fixtures:vulnerable-spring-app} rather than a
 * synthetic call graph, resolved the exact same way as {@code
 * ReachabilityTaggerFixtureIT} in the {@code reachability} module: via {@link
 * Class#getProtectionDomain()} on a class known to live in that module's compiled output. This
 * means the corpus is scored against {@code ReachabilityTagger}'s genuine SootUp-backed behavior,
 * not a stub.
 *
 * <p><b>This corpus must only grow.</b> Every real reachability false-positive or false-negative
 * found in the wild — a case where Reachlayer's tag disagreed with the true runtime reachability
 * of a finding — should be added here as a new permanent {@link LabeledCase} with its correct
 * label documented inline. Cases are never removed, even after the underlying bug is fixed:
 * removing a case would silently delete regression coverage for the exact defect that was once
 * real.
 */
public final class ReachabilityCorpus {

    private ReachabilityCorpus() {}

    /** A single labeled case: a finding plus the reachability tag it should ultimately receive. */
    public record LabeledCase(Finding finding, Reachability expectedLabel) {}

    /**
     * The on-disk classes directory Gradle put on this module's classpath for {@code
     * fixtures:vulnerable-spring-app}, suitable for pointing {@code ReachabilityTagger} at.
     */
    public static Path classesRoot() throws URISyntaxException {
        return Paths.get(
                ReachableVulnerableComponent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    /**
     * The current labeled cases. Append-only — see the class Javadoc. Add new {@link LabeledCase}s
     * here as new ground truth is discovered; never remove an existing one.
     */
    public static List<LabeledCase> cases() {
        return List.of(
                new LabeledCase(
                        scaFinding("dev.reachlayer.fixtures.vulnapp.ReachableVulnerableComponent"),
                        Reachability.REACHABLE),
                new LabeledCase(
                        scaFinding("dev.reachlayer.fixtures.vulnapp.UnreachableVulnerableComponent"),
                        Reachability.UNREACHABLE));
    }

    /** Mirrors {@code ReachabilityTaggerFixtureIT#scaFinding} exactly. */
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
