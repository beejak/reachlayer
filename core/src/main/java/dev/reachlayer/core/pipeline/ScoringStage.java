package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/** Deterministic risk-scoring stage. Implemented by the {@code scoring} module. */
@FunctionalInterface
public interface ScoringStage {
    List<Finding> score(List<Finding> findings);
}
