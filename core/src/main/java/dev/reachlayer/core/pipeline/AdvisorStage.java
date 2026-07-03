package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/** Fix-advisor stage. Implemented by the {@code advisor} module (LLM or templated fallback). */
@FunctionalInterface
public interface AdvisorStage {
    List<Finding> advise(List<Finding> findings);
}
