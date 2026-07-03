package dev.reachlayer.reach.entrypoints;

/**
 * A discovered application entry point: a method the runtime can invoke directly (JVM launcher,
 * servlet container, Spring MVC dispatcher) rather than only via other application code. Entry
 * points seed call-graph construction in {@link dev.reachlayer.reach.callgraph.CallGraphBuilder}.
 *
 * @param className fully-qualified, dot-separated declaring class name
 * @param methodName the entry method's simple name
 * @param description human-readable reason this was classified as an entry point (surfaced in
 *     {@code reachEvidence} text)
 */
public record EntryPoint(String className, String methodName, String description) {}
