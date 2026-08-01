package dev.reachlayer.reach.callgraph;

import java.util.stream.Stream;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.common.constant.MethodHandle;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JDynamicInvokeExpr;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.views.View;

/**
 * A CHA call-graph algorithm that additionally resolves {@code invokedynamic} call sites
 * bootstrapped via {@code java.lang.invoke.LambdaMetafactory} — i.e. Java lambdas and method
 * references — to their actual implementation method, closing the confirmed gap documented in
 * {@code docs/reachability-caveats.md}.
 *
 * <p>SootUp 1.1.2's {@code ClassHierarchyAnalysisAlgorithm.resolveCall} deliberately returns no
 * call targets for <b>any</b> {@code invokedynamic} call site (verified by decompiling
 * {@code sootup.callgraph-1.1.2.jar}: {@code if (invokeExpr instanceof JDynamicInvokeExpr) return
 * Stream.empty();}). This subclass overrides only that one case — using
 * {@code JDynamicInvokeExpr}'s already-parsed bootstrap arguments, which SootUp's ASM-based
 * bytecode frontend resolves into a {@link MethodHandle} constant carrying the real target {@link
 * MethodSignature} — and delegates everything else unchanged to the parent implementation.
 *
 * <p>Not every {@code invokedynamic} site is a lambda: Java 9+ string concatenation also compiles
 * to {@code invokedynamic}, bootstrapped via {@code StringConcatFactory}, which has no "target
 * method" the way a lambda does. {@link #resolveLambdaImplementationMethod} returns {@code null}
 * for anything whose bootstrap arguments don't contain a {@link MethodHandle}, and the call site
 * falls back to the parent's existing (empty) behavior — this class only ever adds edges, never
 * removes ones the unmodified algorithm would have found.
 */
final class LambdaAwareChaAlgorithm extends ClassHierarchyAnalysisAlgorithm {

    LambdaAwareChaAlgorithm(View<? extends SootClass<?>> view) {
        super(view);
    }

    @Override
    protected Stream<MethodSignature> resolveCall(SootMethod sourceMethod, AbstractInvokeExpr invokeExpr) {
        if (invokeExpr instanceof JDynamicInvokeExpr dynamicInvoke) {
            MethodSignature lambdaTarget = resolveLambdaImplementationMethod(dynamicInvoke);
            if (lambdaTarget != null) {
                return Stream.of(lambdaTarget);
            }
        }
        return super.resolveCall(sourceMethod, invokeExpr);
    }

    private static MethodSignature resolveLambdaImplementationMethod(JDynamicInvokeExpr dynamicInvoke) {
        for (Immediate arg : dynamicInvoke.getBootstrapArgs()) {
            if (arg instanceof MethodHandle handle && handle.getMethodSignature() != null) {
                return handle.getMethodSignature();
            }
        }
        return null;
    }
}
