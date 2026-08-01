package dev.reachlayer.fixtures.vulnapp;

/**
 * Simulates a scheduled-task class (e.g. a {@code @Scheduled} method, a cron-triggered job) that
 * the runtime invokes directly but which {@code EntryPointScanner}'s built-in discovery has no
 * rule for — it is a plain class with no Spring MVC or servlet annotation. Deliberately not
 * referenced anywhere else in this fixture app, so it is only reachable at all when a configured
 * {@code entryPoints.extraClasses} override names it (see {@code docs/configuration.md} and
 * {@code ReachabilityTaggerFixtureIT}).
 */
public class NightlyReportJob {

    public String run() {
        return new EntryPointOverrideVulnerableComponent().unsafeMethod();
    }
}
