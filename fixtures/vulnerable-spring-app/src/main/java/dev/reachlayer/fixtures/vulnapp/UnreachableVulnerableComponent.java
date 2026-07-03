package dev.reachlayer.fixtures.vulnapp;

/**
 * Structurally identical to {@link ReachableVulnerableComponent}, but nothing in this fixture app
 * ever constructs this class or calls {@link #unsafeMethod()} — it is genuine dead code from the
 * perspective of every discovered entry point, used to validate the {@code UNREACHABLE} tagging
 * path in {@code ReachabilityTagger}.
 */
public class UnreachableVulnerableComponent {

    public String unsafeMethod() {
        return "unsafe-and-unreachable";
    }
}
