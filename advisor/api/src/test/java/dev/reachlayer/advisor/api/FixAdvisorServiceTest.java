package dev.reachlayer.advisor.api;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.core.config.AdvisorConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.spi.AdvisorContext;
import dev.reachlayer.core.spi.LlmProvider;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class FixAdvisorServiceTest {

    private Finding finding(String id) {
        return Finding.builder()
                .id(id)
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("XSS in " + id)
                .description("Untrusted input rendered without escaping.")
                .build();
    }

    @Test
    void nullProviderUsesTemplatedFallbackForEverything() {
        FixAdvisorService service =
                new FixAdvisorService(null, AdvisorConfig.defaults(), new ContextBuilder(), null);

        List<Finding> result = service.advise(List.of(finding("f1"), finding("f2")));

        assertThat(result).allSatisfy(f -> {
            assertThat(f.fixSuggestion()).isNotNull();
            assertThat(f.fixSuggestion().source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
        });
    }

    @Test
    void onlyTopNFindingsGetRealLlmSuggestions() {
        AtomicInteger calls = new AtomicInteger();
        LlmProvider fakeProvider = new LlmProvider() {
            @Override
            public String name() {
                return "fake";
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public FixSuggestion suggest(Finding f, AdvisorContext context) {
                calls.incrementAndGet();
                return FixSuggestion.llm(FixSuggestion.Type.CODE_FIX, "llm fix for " + f.id(), 0.9);
            }
        };
        AdvisorConfig config = new AdvisorConfig("fake", 2);
        FixAdvisorService service = new FixAdvisorService(fakeProvider, config, new ContextBuilder(), null);

        List<Finding> findings = List.of(finding("f1"), finding("f2"), finding("f3"), finding("f4"));
        List<Finding> result = service.advise(findings);

        assertThat(calls.get()).isEqualTo(2);
        assertThat(result.get(0).fixSuggestion().source()).isEqualTo(FixSuggestion.Source.LLM);
        assertThat(result.get(0).fixSuggestion().text()).isEqualTo("llm fix for f1");
        assertThat(result.get(1).fixSuggestion().source()).isEqualTo(FixSuggestion.Source.LLM);
        assertThat(result.get(1).fixSuggestion().text()).isEqualTo("llm fix for f2");
        assertThat(result.get(2).fixSuggestion().source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
        assertThat(result.get(3).fixSuggestion().source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
    }

    @Test
    void providerFailureDegradesToTemplatedForThatFindingOnly() {
        LlmProvider throwingProvider = new LlmProvider() {
            @Override
            public String name() {
                return "flaky";
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public FixSuggestion suggest(Finding f, AdvisorContext context) {
                throw new RuntimeException("simulated provider failure");
            }
        };
        AdvisorConfig config = new AdvisorConfig("flaky", 5);
        FixAdvisorService service = new FixAdvisorService(throwingProvider, config, new ContextBuilder(), null);

        List<Finding> result = service.advise(List.of(finding("f1"), finding("f2")));

        assertThat(result).hasSize(2);
        assertThat(result).allSatisfy(f -> {
            assertThat(f.fixSuggestion()).isNotNull();
            assertThat(f.fixSuggestion().source()).isEqualTo(FixSuggestion.Source.TEMPLATE);
        });
    }

    @Test
    void everyInputFindingGetsANonNullFixSuggestion() {
        LlmProvider unavailableProvider = new LlmProvider() {
            @Override
            public String name() {
                return "unavailable";
            }

            @Override
            public boolean isAvailable() {
                return false;
            }

            @Override
            public FixSuggestion suggest(Finding f, AdvisorContext context) {
                throw new AssertionError("should never be called when unavailable");
            }
        };
        FixAdvisorService service =
                new FixAdvisorService(unavailableProvider, AdvisorConfig.defaults(), new ContextBuilder(), null);

        List<Finding> findings = List.of(finding("f1"), finding("f2"), finding("f3"));
        List<Finding> result = service.advise(findings);

        assertThat(result).hasSize(findings.size());
        assertThat(result).allSatisfy(f -> assertThat(f.fixSuggestion()).isNotNull());
    }

    @Test
    void inputFindingsAreNotMutated() {
        Finding original = finding("f1");
        FixAdvisorService service =
                new FixAdvisorService(null, AdvisorConfig.defaults(), new ContextBuilder(), null);

        service.advise(List.of(original));

        assertThat(original.fixSuggestion()).isNull();
    }
}
