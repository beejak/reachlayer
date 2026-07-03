package dev.reachlayer.fixtures.vulnapp;

/**
 * Simulates a vulnerable third-party dependency method, the kind an OSV/GHSA advisory would flag
 * (e.g. {@code JndiLookup.lookup} in the real Log4Shell advisory). {@link #unsafeMethod()} IS
 * reachable in this fixture: {@link VulnerableController#reach()} calls it directly from a
 * discovered Spring MVC entry point.
 */
public class ReachableVulnerableComponent {

    public String unsafeMethod() {
        return "unsafe-but-reachable";
    }
}
