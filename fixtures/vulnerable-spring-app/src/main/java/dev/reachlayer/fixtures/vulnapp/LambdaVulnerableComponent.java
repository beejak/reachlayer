package dev.reachlayer.fixtures.vulnapp;

/**
 * Structurally identical to {@link ReachableVulnerableComponent}, but only called from
 * {@link LambdaDispatchController} through a lambda ({@code java.util.function.Supplier}), not a
 * direct method call — used to validate whether SootUp's CHA resolves call edges through
 * {@code invokedynamic}/lambda-metafactory call sites, a specific unsoundness gap flagged (but not
 * previously reproduced) in {@code docs/reachability-caveats.md}.
 */
public class LambdaVulnerableComponent {

    public String unsafeMethod() {
        return "unsafe-and-reachable-only-through-a-lambda";
    }
}
