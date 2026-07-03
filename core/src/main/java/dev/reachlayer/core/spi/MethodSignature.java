package dev.reachlayer.core.spi;

/**
 * A vulnerable method signature as published by an advisory, used to check call-graph
 * reachability at method granularity. {@code methodName} of {@code "*"} means "any method of
 * this class/component" — the coarser, more common case in practice (see PLAN.md §9 risk 2).
 */
public record MethodSignature(String declaringClass, String methodName) {

    public static MethodSignature anyMethodOf(String declaringClass) {
        return new MethodSignature(declaringClass, "*");
    }

    public boolean isWildcard() {
        return "*".equals(methodName);
    }
}
