package dev.reachlayer.output.api;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.RankedReport;
import java.util.List;
import java.util.Locale;

/**
 * Pure Markdown formatting for a {@link RankedReport}. No I/O, no side effects — just string
 * building, so it can be reused by any renderer (console, GitHub PR comment, ...).
 *
 * <p>Shape (see PLAN.md §3.2 / §7): a marker comment on its own first line (so a renderer can
 * find-and-replace its own previous comment), a short heading + summary line, a "Top N" table
 * that is always visible, and a collapsible {@code <details>} block with the remaining ranked
 * findings.
 *
 * <p>Every accessor on {@link Finding} that can be {@code null} or empty is defended against here
 * — this class must never throw on any finding, however sparsely populated.
 */
public final class MarkdownReportFormatter {

    /** Table cells are kept short for readability; longer text is truncated with an ellipsis. */
    private static final int FIX_CELL_MAX_LEN = 150;

    private static final int WHY_CELL_MAX_LEN = 120;

    /**
     * Formats {@code report} as Markdown, prefixed with {@code marker} on its own line.
     *
     * @param report the ranked findings to render
     * @param marker an HTML-comment marker (e.g. {@code "<!-- reachlayer:report -->"}) used by
     *     upserting renderers to locate their own previous comment; may be {@code null}/blank, in
     *     which case no marker line is emitted
     */
    public String format(RankedReport report, String marker) {
        StringBuilder sb = new StringBuilder();

        if (marker != null && !marker.isBlank()) {
            sb.append(marker).append('\n').append('\n');
        }

        String repo = report.repo() == null || report.repo().isBlank() ? "(unknown repo)" : report.repo();
        sb.append("## Reachlayer risk triage — ").append(repo).append('\n').append('\n');

        List<Finding> all = report.findings();
        List<Finding> top = report.top();
        List<Finding> rest = report.rest();

        sb.append(all.size())
                .append(" finding")
                .append(all.size() == 1 ? "" : "s")
                .append(" analyzed, showing top ")
                .append(top.size())
                .append('\n')
                .append('\n');

        appendTable(sb, top, 1);

        if (!rest.isEmpty()) {
            sb.append('\n');
            sb.append("<details>\n");
            sb.append("<summary>Show all ").append(all.size()).append(" findings</summary>\n\n");
            appendTable(sb, rest, top.size() + 1);
            sb.append('\n');
            sb.append("</details>\n");
        }

        return sb.toString();
    }

    private void appendTable(StringBuilder sb, List<Finding> findings, int rankStart) {
        sb.append("| Rank | Risk | Severity | Reachability | CVE / CWE | Finding | Fix |\n");
        sb.append("|---|---|---|---|---|---|---|\n");
        int rank = rankStart;
        for (Finding f : findings) {
            sb.append(buildRow(rank, f)).append('\n');
            rank++;
        }
    }

    private String buildRow(int rank, Finding f) {
        String risk = f.riskScore() == null ? "n/a" : String.format(Locale.ROOT, "%.1f", f.riskScore());
        String severity = sanitizeCell(nonBlank(f.severity(), "unknown"));
        String reachability = f.reachability() == null ? "unknown" : f.reachability().wireValue();
        String cveCwe = joinCveCwe(f);
        String findingCell = buildFindingCell(f);
        String fixCell = buildFixCell(f);

        return "| "
                + rank
                + " | "
                + risk
                + " | "
                + severity
                + " | "
                + reachability
                + " | "
                + cveCwe
                + " | "
                + findingCell
                + " | "
                + fixCell
                + " |";
    }

    private String joinCveCwe(Finding f) {
        List<String> cve = f.cve() == null ? List.of() : f.cve();
        List<String> cwe = f.cwe() == null ? List.of() : f.cwe();
        if (cve.isEmpty() && cwe.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(", ", cve));
        if (!cve.isEmpty() && !cwe.isEmpty()) {
            sb.append(", ");
        }
        sb.append(String.join(", ", cwe));
        return sanitizeCell(sb.toString());
    }

    private String buildFindingCell(Finding f) {
        List<String> parts = new java.util.ArrayList<>();

        String title = nonBlank(f.title(), "(untitled)");
        parts.add("**" + sanitizeCell(title) + "**");

        String location = f.location() == null ? "unknown" : f.location().toString();
        parts.add(sanitizeCell(location));

        if (f.component() != null) {
            parts.add(sanitizeCell(f.component().coordinate()));
        }

        String blast = f.blastRadius() == null ? "" : f.blastRadius().summary();
        if (blast != null && !blast.isBlank()) {
            parts.add(sanitizeCell(blast));
        }

        String why = f.riskExplanation() != null ? f.riskExplanation().render() : "not scored";
        parts.add("why: " + truncate(why, WHY_CELL_MAX_LEN));

        return String.join("<br>", parts);
    }

    private String buildFixCell(Finding f) {
        if (f.fixSuggestion() == null || f.fixSuggestion().text() == null || f.fixSuggestion().text().isBlank()) {
            return "no suggestion available";
        }
        return truncate(f.fixSuggestion().text(), FIX_CELL_MAX_LEN);
    }

    private static String nonBlank(String s, String fallback) {
        return s == null || s.isBlank() ? fallback : s;
    }

    /** Neutralizes characters that would break a Markdown table cell if present in free text. */
    private static String sanitizeCell(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\r\n", " ")
                .replace('\n', ' ')
                .replace('\r', ' ')
                .replace("|", "\\|")
                .trim();
    }

    private static String truncate(String s, int maxLen) {
        String sanitized = sanitizeCell(s);
        if (sanitized.length() <= maxLen) {
            return sanitized;
        }
        int cut = Math.max(0, maxLen - 3);
        return sanitized.substring(0, cut) + "...";
    }
}
