package dev.reachlayer.evals;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.evals.fixtures.ReachabilityCorpus;
import dev.reachlayer.evals.fixtures.ReachabilityCorpus.LabeledCase;
import dev.reachlayer.reach.ReachabilityTagger;
import dev.reachlayer.reach.signatures.ComponentLevelSignatureSource;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Asserts {@code ReachabilityTagger}'s real-world accuracy against {@link ReachabilityCorpus},
 * as opposed to the unit tests in the {@code reachability} module, which verify the tagger's
 * *code* is correct (degrades to {@code UNKNOWN} on failure, wires signatures correctly, etc.).
 * This is a quality eval: does the tagging actually match ground truth.
 */
class ReachabilityAccuracyEvalTest {

    @Test
    void neverTagsATrulyReachableFindingAsUnreachable() throws Exception {
        List<LabeledCase> corpus = ReachabilityCorpus.cases();
        ReachabilityTagger tagger = new ReachabilityTagger(
                ReachabilityCorpus.classesRoot(), List.of(new ComponentLevelSignatureSource()));

        List<Finding> tagged = tagger.tag(corpus.stream().map(LabeledCase::finding).toList());
        Map<String, Finding> taggedById = taggedById(tagged);

        for (LabeledCase labeledCase : corpus) {
            if (labeledCase.expectedLabel() != Reachability.REACHABLE) {
                continue;
            }
            // Hard floor per PLAN.md §9 risk 1 ("prefer under-claiming unreachability"): tagging a
            // truly reachable finding as UNREACHABLE is the dangerous direction — it could bury a
            // real vulnerability. Tagging it UNKNOWN instead would still be a miss worth noticing,
            // but it is not the safety-critical failure mode this assertion exists to catch.
            assertThat(taggedById.get(labeledCase.finding().id()).reachability())
                    .as(
                            "finding %s is truly reachable (ground truth) and must never be tagged UNREACHABLE",
                            labeledCase.finding().id())
                    .isNotEqualTo(Reachability.UNREACHABLE);
        }
    }

    @Test
    void tagsTheKnownUnreachableCaseCorrectly() throws Exception {
        // The corpus is small today (one UNREACHABLE-labeled case), so this asserts an exact
        // match. As the corpus grows with more UNREACHABLE-labeled cases — including genuinely
        // ambiguous ones discovered in the wild — this should likely become a recall/precision
        // threshold over all UNREACHABLE-labeled cases (e.g. "at least 80% correctly tagged")
        // rather than requiring every single one to match exactly.
        List<LabeledCase> corpus = ReachabilityCorpus.cases();
        ReachabilityTagger tagger = new ReachabilityTagger(
                ReachabilityCorpus.classesRoot(), List.of(new ComponentLevelSignatureSource()));

        List<Finding> tagged = tagger.tag(corpus.stream().map(LabeledCase::finding).toList());
        Map<String, Finding> taggedById = taggedById(tagged);

        for (LabeledCase labeledCase : corpus) {
            if (labeledCase.expectedLabel() == Reachability.UNREACHABLE) {
                assertThat(taggedById.get(labeledCase.finding().id()).reachability())
                        .isEqualTo(Reachability.UNREACHABLE);
            }
        }
    }

    /**
     * Matches by {@link Finding#id()} rather than list position: nothing guarantees {@code
     * tagger.tag()} preserves input order, so index-based pairing would silently mismatch if it
     * ever reorders or processes findings in parallel.
     */
    private static Map<String, Finding> taggedById(List<Finding> tagged) {
        Map<String, Finding> byId = new LinkedHashMap<>();
        for (Finding finding : tagged) {
            byId.put(finding.id(), finding);
        }
        return byId;
    }
}
