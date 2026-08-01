package dev.reachlayer.core.config;

import java.util.List;

/**
 * User-supplied additions to {@code EntryPointScanner}'s built-in entry-point discovery
 * (PLAN.md §5 Phase 1, "entry-point overrides"). Reachlayer's discovery only recognizes
 * {@code main}, Spring MVC handler methods, and direct {@code HttpServlet} subclass overrides
 * (see {@code docs/reachability-caveats.md}) — anything else the runtime can invoke directly
 * (a Kafka/JMS listener, a scheduled-task method, a custom framework's dispatch mechanism) is
 * invisible to it, which can cause a genuinely reachable finding to be tagged {@code unreachable}.
 * These overrides let an operator patch that without touching Reachlayer's code.
 *
 * @param extraAnnotations fully-qualified, dot-separated annotation class names (e.g.
 *     {@code "com.example.scheduling.Scheduled"}); any method carrying one of these annotations,
 *     on any class, is treated as an entry point.
 * @param extraClasses fully-qualified, dot-separated class names; every public method declared
 *     directly on one of these classes is treated as an entry point.
 */
public record EntryPointOverrides(List<String> extraAnnotations, List<String> extraClasses) {

    public EntryPointOverrides {
        extraAnnotations = extraAnnotations == null ? List.of() : List.copyOf(extraAnnotations);
        extraClasses = extraClasses == null ? List.of() : List.copyOf(extraClasses);
    }

    public static EntryPointOverrides defaults() {
        return new EntryPointOverrides(List.of(), List.of());
    }
}
