package dev.reachlayer.advisor.providers.anthropic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.spi.AdvisorContext;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AnthropicLlmProviderTest {

    private static final String CANNED_RESPONSE =
            """
            {
              "id": "msg_01",
              "type": "message",
              "role": "assistant",
              "content": [
                { "type": "text", "text": "Upgrade to version 1.2.3 to remediate the deserialization flaw." }
              ],
              "model": "claude-3-5-haiku-latest",
              "stop_reason": "end_turn"
            }
            """;

    private Finding sastFinding() {
        return Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("SQL Injection")
                .description("User input flows into a raw SQL query.")
                .location(new Location("Foo.java", 10, 12, "Foo.query()"))
                .build();
    }

    private Finding scaFinding() {
        return Finding.builder()
                .id("f2")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(Component.of("org.example:lib", "1.0.0"))
                .cve(List.of("CVE-2021-1234"))
                .description("Deserialization vulnerability.")
                .build();
    }

    @Test
    void parsesSuggestionTextFromCannedResponse() {
        AnthropicHttpClient fake = (url, headers, body) -> CANNED_RESPONSE;
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", "claude-3-5-haiku-latest", fake);

        FixSuggestion suggestion = provider.suggest(sastFinding(), AdvisorContext.empty());

        assertThat(suggestion.text()).isEqualTo("Upgrade to version 1.2.3 to remediate the deserialization flaw.");
        assertThat(suggestion.source()).isEqualTo(FixSuggestion.Source.LLM);
        assertThat(suggestion.confidence()).isEqualTo(0.8);
        assertThat(suggestion.type()).isEqualTo(FixSuggestion.Type.CODE_FIX);
    }

    @Test
    void scaFindingWithComponentInfersVersionBumpType() {
        AnthropicHttpClient fake = (url, headers, body) -> CANNED_RESPONSE;
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", null, fake);

        FixSuggestion suggestion = provider.suggest(scaFinding(), AdvisorContext.empty());

        assertThat(suggestion.type()).isEqualTo(FixSuggestion.Type.VERSION_BUMP);
    }

    @Test
    void isAvailableReflectsConstructorInjectedApiKey() {
        AnthropicHttpClient fake = (url, headers, body) -> CANNED_RESPONSE;

        assertThat(new AnthropicLlmProvider("sk-real-key", null, fake).isAvailable()).isTrue();
        assertThat(new AnthropicLlmProvider(null, null, fake).isAvailable()).isFalse();
        assertThat(new AnthropicLlmProvider("  ", null, fake).isAvailable()).isFalse();
    }

    @Test
    void requestBodyContainsModelAndFindingDerivedContent() {
        StringBuilder capturedUrl = new StringBuilder();
        Map<String, String>[] capturedHeaders = new Map[1];
        StringBuilder capturedBody = new StringBuilder();
        AnthropicHttpClient captor = (url, headers, body) -> {
            capturedUrl.append(url);
            capturedHeaders[0] = headers;
            capturedBody.append(body);
            return CANNED_RESPONSE;
        };

        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", "claude-3-5-sonnet-latest", captor);
        provider.suggest(sastFinding(), AdvisorContext.empty());

        assertThat(capturedUrl.toString()).isEqualTo("https://api.anthropic.com/v1/messages");
        assertThat(capturedHeaders[0]).containsEntry("x-api-key", "sk-test");
        assertThat(capturedHeaders[0]).containsEntry("anthropic-version", "2023-06-01");
        assertThat(capturedHeaders[0]).containsEntry("content-type", "application/json");
        assertThat(capturedBody.toString()).contains("\"model\":\"claude-3-5-sonnet-latest\"");
        assertThat(capturedBody.toString()).contains("SQL Injection");
        assertThat(capturedBody.toString()).contains("Foo.query()");
    }

    @Test
    void defaultModelUsedWhenNoneProvided() {
        StringBuilder capturedBody = new StringBuilder();
        AnthropicHttpClient captor = (url, headers, body) -> {
            capturedBody.append(body);
            return CANNED_RESPONSE;
        };
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", null, captor);

        provider.suggest(sastFinding(), AdvisorContext.empty());

        assertThat(capturedBody.toString()).contains("claude-3-5-haiku-latest");
    }

    @Test
    void httpFailurePropagatesAsRuntimeException() {
        AnthropicHttpClient failing = (url, headers, body) -> {
            throw new IOException("connection reset");
        };
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", null, failing);

        assertThatThrownBy(() -> provider.suggest(sastFinding(), AdvisorContext.empty()))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(IOException.class);
    }

    @Test
    void unparseableResponsePropagatesAsRuntimeException() {
        AnthropicHttpClient malformed = (url, headers, body) -> "{ not valid json";
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", null, malformed);

        assertThatThrownBy(() -> provider.suggest(sastFinding(), AdvisorContext.empty()))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void missingContentFieldPropagatesAsRuntimeException() {
        AnthropicHttpClient noContent = (url, headers, body) -> "{ \"id\": \"msg_01\" }";
        AnthropicLlmProvider provider = new AnthropicLlmProvider("sk-test", null, noContent);

        assertThatThrownBy(() -> provider.suggest(sastFinding(), AdvisorContext.empty()))
                .isInstanceOf(RuntimeException.class);
    }
}
