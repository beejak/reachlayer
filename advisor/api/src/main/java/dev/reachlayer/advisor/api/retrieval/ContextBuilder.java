package dev.reachlayer.advisor.api.retrieval;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.spi.AdvisorContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Assembles the {@link AdvisorContext} handed to an {@code LlmProvider} (or the templated
 * fallback) for a single finding: the advisory text, a best-effort code snippet around the
 * offending lines, and a short dependency summary. See PLAN.md §7 ({@code advisor/retrieval}).
 *
 * <p>Retrieval is deliberately best-effort: a missing file, an unknown repo root, or an I/O
 * error must never fail the pipeline (PLAN.md's "never fail the build" principle) — those cases
 * simply degrade to a {@code null} snippet.
 */
public final class ContextBuilder {

    private static final Logger log = LoggerFactory.getLogger(ContextBuilder.class);

    /** Extra lines of context pulled in on either side of the finding's reported line range. */
    private static final int SNIPPET_PADDING_LINES = 3;

    /**
     * Builds the {@link AdvisorContext} for {@code finding}.
     *
     * @param finding the finding to build context for; must not be {@code null}
     * @param repoRoot the repository root used to resolve {@link Location#file()}, or {@code
     *     null} if unknown (in which case no code snippet is retrieved)
     */
    public AdvisorContext buildContext(Finding finding, Path repoRoot) {
        String advisoryText = finding.description();
        String codeSnippet = readSnippet(finding.location(), repoRoot);
        String dependencyContext = buildDependencyContext(finding.component(), finding.cve());
        return new AdvisorContext(advisoryText, codeSnippet, dependencyContext);
    }

    private String readSnippet(Location location, Path repoRoot) {
        if (location == null || location.file() == null || repoRoot == null) {
            return null;
        }
        Path file;
        try {
            file = repoRoot.resolve(location.file());
        } catch (RuntimeException e) {
            log.debug("Could not resolve snippet path for {} under {}: {}", location.file(), repoRoot, e.toString());
            return null;
        }
        try {
            List<String> lines = Files.readAllLines(file);
            if (lines.isEmpty()) {
                return null;
            }
            int startLine = location.startLine() == null ? 1 : location.startLine();
            int endLine = location.endLine() == null ? startLine : location.endLine();

            // Convert 1-based, inclusive line numbers to a 0-based, padded, clamped range.
            int fromIndex = Math.max(0, (startLine - 1) - SNIPPET_PADDING_LINES);
            int toIndexExclusive = Math.min(lines.size(), endLine + SNIPPET_PADDING_LINES);
            if (fromIndex >= toIndexExclusive) {
                return null;
            }
            return String.join("\n", lines.subList(fromIndex, toIndexExclusive));
        } catch (IOException | RuntimeException e) {
            log.debug("Could not read code snippet from {}: {}", file, e.toString());
            return null;
        }
    }

    private String buildDependencyContext(Component component, List<String> cve) {
        if (component == null) {
            return null;
        }
        String cveList = (cve == null || cve.isEmpty()) ? "none known" : String.join(",", cve);
        return component.coordinate() + " (CVEs: " + cveList + ")";
    }
}
