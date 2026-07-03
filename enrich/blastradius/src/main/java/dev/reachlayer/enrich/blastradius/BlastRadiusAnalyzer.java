package dev.reachlayer.enrich.blastradius;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Location;
import java.util.List;
import java.util.Locale;

/**
 * Heuristic blast-radius analyzer. See PLAN.md §3.1, §8, and the §9 open question "minimum
 * viable blast-radius heuristic set that's accurate enough to trust."
 *
 * <p>This is deliberately a simple keyword-matching heuristic over data already present on a
 * {@link Finding} (file path, title, description, component name, method signature) — it does
 * <em>not</em> use the call graph, so it stays decoupled from the {@code reachability} module.
 * A future, more precise implementation could walk the call graph to confirm a finding is
 * actually reachable from an HTTP handler, or resolve component transitively to find real
 * downstream consumers; both are out of scope for this MVP.
 *
 * <p><b>Conservative by design:</b> the project's core principle for reachability is "never
 * under-claim risk" (prefer `Unknown` over wrongly saying `Unreachable`). Blast-radius heuristics
 * run in the *opposite* direction: weak/absent keyword signal deliberately resolves to
 * {@code false} rather than {@code true}. The two policies are mirror images of the same
 * underlying value — be honest about what a cheap heuristic can and can't tell you, rather than
 * overclaiming precision it doesn't have. Concretely: this analyzer will produce false negatives
 * (e.g. a method named {@code processRequest} that touches auth but doesn't say so) far more
 * often than false positives, and that trade-off is intentional for an advisory, non-blocking
 * tool where noisy over-flagging erodes developer trust faster than an occasional miss.
 */
public final class BlastRadiusAnalyzer {

    private static final List<String> INTERNET_FACING_KEYWORDS =
            List.of("controller", "rest", "servlet", "endpoint", "handler", "@requestmapping");

    private static final List<String> AUTH_KEYWORDS =
            List.of("auth", "login", "password", "credential", "jwt", "oauth", "session", "security");

    private static final List<String> PII_KEYWORDS = List.of(
            "user", "email", "ssn", "address", "phone", "profile", "personal", "customer", "pii");

    private static final List<String> SECRETS_KEYWORDS = List.of(
            "secret",
            "apikey",
            "api_key",
            "api-key",
            "token",
            "privatekey",
            "private_key",
            "vault",
            "credential");

    /**
     * Computes a {@link BlastRadius} for {@code finding} purely from string heuristics over its
     * existing fields. Never throws; a finding with no matching keywords yields the all-false
     * {@link BlastRadius#NONE}-equivalent result.
     */
    public BlastRadius analyze(Finding finding) {
        String haystack = buildHaystack(finding);

        boolean internetFacing = containsAny(haystack, INTERNET_FACING_KEYWORDS);
        boolean touchesAuth = containsAny(haystack, AUTH_KEYWORDS);
        boolean touchesPii = containsAny(haystack, PII_KEYWORDS);
        boolean touchesSecrets = containsAny(haystack, SECRETS_KEYWORDS);

        // MVP placeholder: a real "what this touches downstream" signal would walk the
        // dependency/call graph; here we just surface the finding's own component coordinate,
        // if any, as the sole downstream entry. Deeper downstream analysis is out of scope.
        Component component = finding.component();
        List<String> downstream = component != null ? List.of(component.coordinate()) : List.of();

        return new BlastRadius(internetFacing, touchesAuth, touchesPii, touchesSecrets, downstream);
    }

    private static String buildHaystack(Finding finding) {
        Location location = finding.location();
        Component component = finding.component();

        StringBuilder sb = new StringBuilder();
        appendIfPresent(sb, location == null ? null : location.file());
        appendIfPresent(sb, location == null ? null : location.methodSignature());
        appendIfPresent(sb, finding.title());
        appendIfPresent(sb, finding.description());
        appendIfPresent(sb, component == null ? null : component.name());

        return sb.toString().toLowerCase(Locale.ROOT);
    }

    private static void appendIfPresent(StringBuilder sb, String value) {
        if (value != null && !value.isBlank()) {
            sb.append(value).append(' ');
        }
    }

    private static boolean containsAny(String haystack, List<String> keywords) {
        for (String keyword : keywords) {
            if (haystack.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
