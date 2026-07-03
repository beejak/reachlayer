package dev.reachlayer.advisor.providers.noop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.spi.AdvisorContext;
import java.util.List;
import org.junit.jupiter.api.Test;

class NoopLlmProviderTest {

    private final NoopLlmProvider provider = new NoopLlmProvider();

    @Test
    void isAlwaysAvailable() {
        assertThat(provider.isAvailable()).isTrue();
    }

    @Test
    void nameIsNoop() {
        assertThat(provider.name()).isEqualTo("noop");
    }

    @Test
    void scaFindingProducesVersionBumpMentioningComponentAndCves() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(Component.of("org.example:lib", "1.0.0"))
                .cve(List.of("CVE-2021-1234"))
                .description("Known deserialization vulnerability.")
                .build();

        FixSuggestion suggestion = provider.suggest(finding, AdvisorContext.empty());

        assertThat(suggestion.type()).isEqualTo(FixSuggestion.Type.VERSION_BUMP);
        assertThat(suggestion.source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
        assertThat(suggestion.text()).contains("org.example:lib@1.0.0").contains("CVE-2021-1234");
        assertThat(suggestion.text()).isNotBlank();
    }

    @Test
    void sastFindingProducesCodeFixMentioningTitle() {
        Finding finding = Finding.builder()
                .id("f2")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("SQL Injection")
                .description("User input flows into a raw SQL query.")
                .location(new Location("Foo.java", 10, 12, "Foo.query()"))
                .build();

        FixSuggestion suggestion = provider.suggest(finding, AdvisorContext.empty());

        assertThat(suggestion.type()).isEqualTo(FixSuggestion.Type.CODE_FIX);
        assertThat(suggestion.source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
        assertThat(suggestion.text()).contains("SQL Injection");
        assertThat(suggestion.text()).containsIgnoringCase("parameterized queries");
    }

    @Test
    void unrecognizedFindingProducesNonBlankConfigSuggestion() {
        Finding finding = Finding.builder()
                .id("f3")
                .source("other")
                .kind(FindingKind.SCA) // SCA without a component falls through to the generic branch
                .title("Odd finding")
                .build();

        FixSuggestion suggestion = provider.suggest(finding, AdvisorContext.empty());

        assertThat(suggestion.type()).isEqualTo(FixSuggestion.Type.CONFIG);
        assertThat(suggestion.text()).isNotBlank().contains("Odd finding");
    }

    @Test
    void neverProducesBlankTextForAnyFindingKind() {
        for (FindingKind kind : FindingKind.values()) {
            Finding finding = Finding.builder().id("f-" + kind).source("s").kind(kind).build();

            assertThatCode(() -> provider.suggest(finding, AdvisorContext.empty())).doesNotThrowAnyException();
            assertThat(provider.suggest(finding, AdvisorContext.empty()).text()).isNotBlank();
        }
    }
}
