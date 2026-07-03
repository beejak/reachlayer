package dev.reachlayer.core.pipeline;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/** EPSS + KEV + blast-radius enrichment stage. Implemented by the {@code enrich} module. */
@FunctionalInterface
public interface EnrichmentStage {
    List<Finding> enrich(List<Finding> findings);
}
