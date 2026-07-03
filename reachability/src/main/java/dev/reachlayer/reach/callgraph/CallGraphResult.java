package dev.reachlayer.reach.callgraph;

import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.callgraph.CallGraph;
import sootup.core.model.SootMethod;
import sootup.core.types.ClassType;
import sootup.java.core.JavaSootClass;
import sootup.java.core.views.JavaView;

/**
 * A successfully-constructed CHA call graph plus the resolved SootUp view it was built over.
 * Queries are resolved lazily/on-demand against the view (a single class lookup, not a full
 * classpath scan) so that checking reachability for a handful of findings stays cheap regardless
 * of how large the analyzed classpath is (PLAN.md §9 risk 3).
 */
public final class CallGraphResult {

    private static final Logger log = LoggerFactory.getLogger(CallGraphResult.class);

    private final JavaView view;
    private final CallGraph callGraph;
    private final List<String> seedEntryPointLabels;

    CallGraphResult(JavaView view, CallGraph callGraph, List<String> seedEntryPointLabels) {
        this.view = view;
        this.callGraph = callGraph;
        this.seedEntryPointLabels = List.copyOf(seedEntryPointLabels);
    }

    /**
     * Whether {@code fullyQualifiedClassName} was found at all in the analyzed classpath — i.e.
     * whether we have any basis for an opinion on it, independent of whether it turned out to be
     * reachable.
     */
    public boolean isClassObserved(String fullyQualifiedClassName) {
        return resolveClass(fullyQualifiedClassName).isPresent();
    }

    /**
     * Whether any method declared directly on {@code fullyQualifiedClassName} (matching
     * {@code methodNameOrNull} if given, or any method at all if {@code null} — the
     * component-level wildcard case) is present in the call graph, i.e. transitively reachable
     * from one of the seed entry points.
     */
    public boolean isReachable(String fullyQualifiedClassName, String methodNameOrNull) {
        Optional<JavaSootClass> sootClass = resolveClass(fullyQualifiedClassName);
        if (sootClass.isEmpty()) {
            return false;
        }
        for (SootMethod method : sootClass.get().getMethods()) {
            if (methodNameOrNull == null || method.getName().equals(methodNameOrNull)) {
                if (callGraph.containsMethod(method.getSignature())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Short human-readable summary of the entry point(s) the call graph was seeded from. */
    public String entryPointSummary() {
        if (seedEntryPointLabels.isEmpty()) {
            return "an unspecified entry point";
        }
        if (seedEntryPointLabels.size() <= 3) {
            return String.join(", ", seedEntryPointLabels);
        }
        return String.join(", ", seedEntryPointLabels.subList(0, 3))
                + " and "
                + (seedEntryPointLabels.size() - 3)
                + " more";
    }

    private Optional<JavaSootClass> resolveClass(String fullyQualifiedClassName) {
        try {
            ClassType classType = view.getIdentifierFactory().getClassType(fullyQualifiedClassName);
            return view.getClass(classType);
        } catch (RuntimeException e) {
            log.debug("Could not resolve class {} in SootUp view: {}", fullyQualifiedClassName, e.toString());
            return Optional.empty();
        }
    }
}
