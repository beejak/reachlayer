package dev.reachlayer.core.model;

/**
 * Reachlayer's additive reachability tag. Static reachability analysis is unsound (it can miss
 * real call paths through reflection, dependency injection, or config-driven wiring), so this
 * tag is used only for ranking and grouping — it must never be used to hide or drop a finding.
 *
 * <p>When in doubt, tag {@link #UNKNOWN} rather than {@link #UNREACHABLE}.
 */
public enum Reachability {
    REACHABLE,
    UNREACHABLE,
    UNKNOWN;

    public String wireValue() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
