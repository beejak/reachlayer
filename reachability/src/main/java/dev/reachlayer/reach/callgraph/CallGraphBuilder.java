package dev.reachlayer.reach.callgraph;

import dev.reachlayer.reach.entrypoints.EntryPoint;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.callgraph.CallGraph;
import sootup.callgraph.CallGraphAlgorithm;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.model.SootMethod;
import sootup.core.model.SourceType;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.bytecode.inputlocation.JrtFileSystemAnalysisInputLocation;
import sootup.java.bytecode.inputlocation.PathBasedAnalysisInputLocation;
import sootup.java.core.JavaProject;
import sootup.java.core.JavaSootClass;
import sootup.java.core.language.JavaLanguage;
import sootup.java.core.views.JavaView;

/**
 * Builds a Class Hierarchy Analysis (CHA) call graph, via SootUp, over a directory or jar of
 * compiled classes ("the app under analysis"), seeded from the entry points discovered by {@link
 * dev.reachlayer.reach.entrypoints.EntryPointScanner}.
 *
 * <p>CHA (rather than RTA/VTA) is used deliberately per PLAN.md §4/§9 risk 3: it is the cheapest,
 * most over-approximating call-graph algorithm SootUp offers, which is the right trade-off for an
 * "additive, never suppressive" reachability signal computed at CI speed — see PLAN.md §9 risk 1
 * ("prefer under-claiming unreachability").
 *
 * <p>Class/method resolution against the resulting {@link JavaView} is done lazily, one class at a
 * time (see {@link CallGraphResult}), rather than eagerly resolving the entire classpath — eagerly
 * calling {@code JavaView.getClasses()} would force SootUp to parse every class on every input
 * location (including the full JDK runtime image, if included), which is exactly the "1-8 hour
 * scan" problem PLAN.md §9 risk 3 warns about.
 */
public final class CallGraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(CallGraphBuilder.class);

    /** Analyze against a reasonably current language level; only affects body-interceptor
     * selection, not which classes resolve. */
    private static final int JAVA_LANGUAGE_LEVEL = 17;

    public CallGraphResult build(Path classesRoot, List<EntryPoint> entryPoints) throws CallGraphException {
        if (entryPoints == null || entryPoints.isEmpty()) {
            throw new CallGraphException("no entry points discovered under " + classesRoot);
        }

        // Fall back to excluding the JDK runtime image on ANY failure of the full pipeline (view
        // construction OR CHA construction), not merely view construction — SootUp's type-hierarchy
        // resolution has been observed to throw only once CHA actually walks the hierarchy, well
        // after view construction itself succeeds. Excluding the JDK runtime also keeps analysis
        // cheap (PLAN.md §9 risk 3) and is sufficient for app-to-app/app-to-dependency reachability,
        // which is all this tagger needs.
        try {
            return buildOnce(classesRoot, entryPoints, true);
        } catch (RuntimeException e) {
            log.debug(
                    "Falling back to a call graph without JDK runtime classes for {}: {}", classesRoot, e.toString());
            try {
                return buildOnce(classesRoot, entryPoints, false);
            } catch (RuntimeException e2) {
                throw new CallGraphException("CHA call graph construction failed for " + classesRoot, e2);
            }
        }
    }

    private CallGraphResult buildOnce(Path classesRoot, List<EntryPoint> entryPoints, boolean includeJdkRuntime) {
        JavaView view = createView(classesRoot, includeJdkRuntime);

        List<MethodSignature> seeds = new ArrayList<>();
        List<String> resolvedLabels = new ArrayList<>();
        for (EntryPoint entryPoint : entryPoints) {
            resolveEntryPoint(view, entryPoint, seeds, resolvedLabels);
        }
        if (seeds.isEmpty()) {
            throw new IllegalStateException(
                    "none of the "
                            + entryPoints.size()
                            + " discovered entry point(s) resolved to a method in the analyzed classes at "
                            + classesRoot);
        }

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        CallGraph callGraph = cha.initialize(seeds);
        return new CallGraphResult(view, callGraph, resolvedLabels);
    }

    private JavaView createView(Path classesRoot, boolean includeJdkRuntime) {
        JavaLanguage language = new JavaLanguage(JAVA_LANGUAGE_LEVEL);
        // PathBasedAnalysisInputLocation wraps a java.nio.file.Path directly (auto-detecting a
        // directory vs. jar/war/apk), rather than JavaClassPathAnalysisInputLocation's
        // string-classpath parsing, which mishandles paths containing spaces (common on Windows,
        // e.g. "C:\...\Git Projects\..."). Must use the (Path, SourceType) constructor: the
        // single-arg constructor leaves the internal delegate uninitialized (a bug/footgun in
        // SootUp 1.1.2 — verified by decompiling the class) and NPEs on first use.
        JavaProject.JavaProjectBuilder builder =
                JavaProject.builder(language)
                        .addInputLocation(
                                new PathBasedAnalysisInputLocation(classesRoot, SourceType.Application));
        if (includeJdkRuntime) {
            builder = builder.addInputLocation(new JrtFileSystemAnalysisInputLocation());
        }
        return builder.build().createView();
    }

    private void resolveEntryPoint(
            JavaView view, EntryPoint entryPoint, List<MethodSignature> seeds, List<String> resolvedLabels) {
        try {
            ClassType classType = view.getIdentifierFactory().getClassType(entryPoint.className());
            Optional<JavaSootClass> sootClass = view.getClass(classType);
            if (sootClass.isEmpty()) {
                log.debug("Entry point class {} was not resolved by SootUp; skipping", entryPoint.className());
                return;
            }
            boolean matched = false;
            for (SootMethod method : sootClass.get().getMethods()) {
                if (method.getName().equals(entryPoint.methodName())) {
                    seeds.add(method.getSignature());
                    matched = true;
                }
            }
            if (matched) {
                resolvedLabels.add(
                        entryPoint.className() + "." + entryPoint.methodName() + " (" + entryPoint.description() + ")");
            }
        } catch (RuntimeException e) {
            log.debug(
                    "Failed to resolve entry point {}#{}: {}",
                    entryPoint.className(),
                    entryPoint.methodName(),
                    e.toString());
        }
    }
}
