package dev.reachlayer.fixtures.vulnapp;

/**
 * Structurally identical to {@link ReachableVulnerableComponent}, but only called from
 * {@link NightlyReportJob#run()} — a plain class with no Spring/servlet annotation that
 * {@code EntryPointScanner}'s built-in discovery does not recognize as an entry point on its own.
 * Used to validate that a configured {@code entryPoints.extraClasses} override (see
 * {@code docs/configuration.md}) correctly flips this from {@code UNREACHABLE} to {@code
 * REACHABLE} once {@code NightlyReportJob} is treated as an entry point.
 */
public class EntryPointOverrideVulnerableComponent {

    public String unsafeMethod() {
        return "unsafe-and-reachable-only-through-a-configured-entry-point-override";
    }
}
