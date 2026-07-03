package dev.reachlayer.reach.callgraph;

/**
 * Thrown when a SootUp call graph cannot be constructed for the given input (unresolvable
 * classpath, no discoverable/resolvable entry points, an internal SootUp failure, ...).
 *
 * <p>Callers (see {@code dev.reachlayer.reach.ReachabilityTagger}) must treat this as a signal to
 * degrade every affected finding to {@link dev.reachlayer.core.model.Reachability#UNKNOWN} rather
 * than propagate a failure — static reachability is inherently best-effort (PLAN.md §9 risk 1).
 */
public final class CallGraphException extends Exception {

    public CallGraphException(String message) {
        super(message);
    }

    public CallGraphException(String message, Throwable cause) {
        super(message, cause);
    }
}
