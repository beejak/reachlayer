package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/**
 * Reachability tagging stage. Implemented by {@code reachability}'s {@code ReachabilityTagger}.
 * Defined here (rather than {@code core} depending on {@code reachability}) so {@code core} has
 * no dependency on the heavier analysis modules; {@code cmd} wires the concrete implementation
 * in via a method reference.
 */
@FunctionalInterface
public interface ReachabilityStage {
    List<Finding> tag(List<Finding> findings);
}
