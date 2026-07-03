package dev.reachlayer.advisor.providers.anthropic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.FixSuggestion;
import dev.reachlayer.core.spi.AdvisorContext;
import dev.reachlayer.core.spi.LlmProvider;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@link LlmProvider} backed by the Anthropic Messages API ({@code POST
 * https://api.anthropic.com/v1/messages}) — the default reference LLM implementation per PLAN.md
 * §7/§10. Falls back to nothing itself: if the HTTP call fails or the response can't be parsed,
 * this class lets the exception propagate as a {@link RuntimeException}. It is the caller's job
 * (the {@code advisor:api} {@code FixAdvisorService}) to catch that and degrade to the templated
 * fallback — this class's only job is to make a real, correct attempt.
 */
public final class AnthropicLlmProvider implements LlmProvider {

    private static final String API_URL = "https://api.anthropic.com/v1/messages";
    private static final String ANTHROPIC_VERSION = "2023-06-01";

    /**
     * Default model id used when {@code ANTHROPIC_MODEL} is unset. Anthropic periodically
     * introduces newer models; this is simply a reasonable, inexpensive current default and is
     * fully overridable via the environment variable.
     */
    private static final String DEFAULT_MODEL = "claude-3-5-haiku-latest";

    private static final int MAX_TOKENS = 500;

    /**
     * Fixed placeholder confidence used for every suggestion this provider returns. Real
     * confidence calibration is out of scope for the MVP; 0.8 is simply meant to read as "more
     * trustworthy than the 0.5 templated fallback" (see {@link FixSuggestion#template}).
     */
    private static final double LLM_CONFIDENCE = 0.8;

    private final String apiKey;
    private final String model;
    private final AnthropicHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * @param apiKey the Anthropic API key, or {@code null}/blank if unavailable (see {@link
     *     #isAvailable()})
     * @param model the model id to use, e.g. {@code "claude-3-5-haiku-latest"}; if {@code
     *     null}/blank, {@link #DEFAULT_MODEL} is used
     * @param httpClient the HTTP transport to use; production code should pass a {@link
     *     JdkAnthropicHttpClient}, tests can pass a fake
     */
    public AnthropicLlmProvider(String apiKey, String model, AnthropicHttpClient httpClient) {
        this.apiKey = apiKey;
        this.model = (model == null || model.isBlank()) ? DEFAULT_MODEL : model;
        this.httpClient = httpClient;
    }

    /**
     * Builds a provider wired to the real network, reading {@code ANTHROPIC_API_KEY} (may be
     * unset/blank — see {@link #isAvailable()}) and {@code ANTHROPIC_MODEL} (defaults to {@link
     * #DEFAULT_MODEL} if unset) from the environment.
     */
    public static AnthropicLlmProvider fromEnvironment() {
        String apiKey = System.getenv("ANTHROPIC_API_KEY");
        String model = System.getenv("ANTHROPIC_MODEL");
        return new AnthropicLlmProvider(apiKey, model, new JdkAnthropicHttpClient());
    }

    @Override
    public String name() {
        return "anthropic";
    }

    @Override
    public boolean isAvailable() {
        return apiKey != null && !apiKey.isBlank();
    }

    @Override
    public FixSuggestion suggest(Finding finding, AdvisorContext context) {
        try {
            String prompt = buildPrompt(finding, context);
            String requestBody = buildRequestBody(prompt);

            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("x-api-key", apiKey);
            headers.put("anthropic-version", ANTHROPIC_VERSION);
            headers.put("content-type", "application/json");

            String responseBody = httpClient.post(API_URL, headers, requestBody);
            String text = extractText(responseBody);

            FixSuggestion.Type type = (finding.kind() == FindingKind.SCA && finding.component() != null)
                    ? FixSuggestion.Type.VERSION_BUMP
                    : FixSuggestion.Type.CODE_FIX;
            return FixSuggestion.llm(type, text, LLM_CONFIDENCE);
        } catch (IOException e) {
            throw new RuntimeException("Anthropic API call failed for finding " + finding.id(), e);
        }
    }

    private String buildPrompt(Finding finding, AdvisorContext context) {
        Component component = finding.component();
        StringBuilder sb = new StringBuilder();
        sb.append("You are a security remediation assistant. Provide a concise, actionable fix for the ")
                .append("following finding. Respond with only the remediation guidance, no preamble.\n\n");
        sb.append("Finding kind: ").append(finding.kind()).append('\n');
        sb.append("Title: ").append(orNone(finding.title())).append('\n');
        sb.append("Description: ").append(orNone(finding.description())).append('\n');
        sb.append("Location: ").append(finding.location()).append('\n');
        if (component != null) {
            sb.append("Component: ").append(component.coordinate()).append('\n');
        }
        if (!finding.cve().isEmpty()) {
            sb.append("CVEs: ").append(String.join(", ", finding.cve())).append('\n');
        }
        if (context != null) {
            if (context.advisoryText() != null) {
                sb.append("Advisory text: ").append(context.advisoryText()).append('\n');
            }
            if (context.dependencyContext() != null) {
                sb.append("Dependency context: ").append(context.dependencyContext()).append('\n');
            }
            if (context.codeSnippet() != null) {
                sb.append("Offending code snippet:\n").append(context.codeSnippet()).append('\n');
            }
        }
        return sb.toString();
    }

    private static String orNone(String s) {
        return (s == null || s.isBlank()) ? "(none provided)" : s;
    }

    private String buildRequestBody(String prompt) {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("model", model);
        root.put("max_tokens", MAX_TOKENS);
        ArrayNode messages = root.putArray("messages");
        ObjectNode message = messages.addObject();
        message.put("role", "user");
        message.put("content", prompt);
        try {
            return objectMapper.writeValueAsString(root);
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize Anthropic request body", e);
        }
    }

    /**
     * Parses the Anthropic Messages API response shape: {@code {"content":[{"type":"text",
     * "text":"..."}], ...}}.
     */
    private String extractText(String responseBody) throws IOException {
        JsonNode root = objectMapper.readTree(responseBody);
        JsonNode content = root.get("content");
        if (content == null || !content.isArray() || content.isEmpty()) {
            throw new IOException("Anthropic response had no content array: " + responseBody);
        }
        JsonNode textNode = content.get(0).get("text");
        if (textNode == null || textNode.asText().isBlank()) {
            throw new IOException("Anthropic response content[0] had no text field: " + responseBody);
        }
        return textNode.asText();
    }
}
