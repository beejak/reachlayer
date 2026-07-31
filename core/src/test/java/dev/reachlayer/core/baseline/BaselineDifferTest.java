package dev.reachlayer.core.baseline;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BaselineDifferTest {

    @Test
    void tagsFindingAbsentFromBaselineAsNewAndPresentAsNotNew() {
        Finding newFinding = Finding.builder().id("f-new").source("fortify").kind(FindingKind.SAST).build();
        Finding existingFinding = Finding.builder().id("f-old").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> tagged = BaselineDiffer.tag(List.of(newFinding, existingFinding), Set.of("f-old"));

        assertThat(tagged)
                .extracting(Finding::id, Finding::isNew)
                .containsExactly(tuple("f-new", true), tuple("f-old", false));
    }

    @Test
    void returnsFindingsUnchangedWhenBaselineIdsIsNull() {
        Finding finding = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> result = BaselineDiffer.tag(List.of(finding), null);

        assertThat(result).containsExactly(finding); // identity: same reference
        assertThat(result.get(0).isNew()).isNull();
    }

    @Test
    void emptyBaselineTagsEveryFindingAsNew() {
        Finding finding = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> tagged = BaselineDiffer.tag(List.of(finding), Set.of());

        assertThat(tagged.get(0).isNew()).isTrue();
    }
}
