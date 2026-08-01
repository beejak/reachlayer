package dev.reachlayer.output.sarif;

import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.RankedReport;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Pure mapping from a {@link RankedReport} to a {@link SarifModel.SarifLog} — no I/O, no side
 * effects, just object-graph building, mirroring {@code output/api}'s {@code
 * MarkdownReportFormatter} split of "pure formatting" vs. "I/O renderer". Every {@link Finding}
 * accessor that can be {@code null}/empty is defended against here — this class must never throw,
 * however sparsely populated a finding is (see the design spec's "Non-blocking guarantee").
 */
public final class SarifReportBuilder {

    private static final String SCHEMA_URI =
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    private static final String SARIF_VERSION = "2.1.0";
    private static final String TOOL_NAME = "Reachlayer";
    private static final String TOOL_INFORMATION_URI = "https://github.com/reachlayer/reachlayer";
    private static final String TOOL_VERSION = "0.1.0-SNAPSHOT";

    private static final double ERROR_THRESHOLD = 75.0;
    private static final double WARNING_THRESHOLD = 40.0;

    private static final int TITLE_MAX_LEN = 200;

    private SarifReportBuilder() {
    }

    public static SarifModel.SarifLog build(RankedReport report) {
        List<Finding> findings = report.findings();

        Map<String, Integer> ruleIndexById = new LinkedHashMap<>();
        List<SarifModel.SarifRule> rules = new ArrayList<>();
        List<SarifModel.SarifResult> results = new ArrayList<>(findings.size());

        for (Finding f : findings) {
            String ruleId = ruleId(f);
            Integer index = ruleIndexById.get(ruleId);
            if (index == null) {
                index = rules.size();
                ruleIndexById.put(ruleId, index);
                rules.add(buildRule(ruleId, f));
            }
            results.add(buildResult(f, ruleId, index));
        }

        SarifModel.SarifDriver driver = new SarifModel.SarifDriver(TOOL_NAME, TOOL_INFORMATION_URI, TOOL_VERSION, rules);
        SarifModel.SarifRun run = new SarifModel.SarifRun(new SarifModel.SarifTool(driver), results);
        return new SarifModel.SarifLog(SCHEMA_URI, SARIF_VERSION, List.of(run));
    }

    // --- rule id ---

    static String ruleId(Finding f) {
        String discriminator;
        if (!f.cwe().isEmpty()) {
            discriminator = f.cwe().get(0);
        } else if (!f.cve().isEmpty()) {
            discriminator = f.cve().get(0);
        } else {
            discriminator = slug(f.title());
        }
        return f.source() + ":" + discriminator;
    }

    private static String slug(String text) {
        if (text == null || text.isBlank()) {
            return "unspecified";
        }
        String slugged = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
        return slugged.isBlank() ? "unspecified" : slugged;
    }

    // --- rule ---

    private static SarifModel.SarifRule buildRule(String ruleId, Finding f) {
        String title = nonBlank(f.title(), ruleId);
        SarifModel.SarifText shortDescription = new SarifModel.SarifText(truncate(title, TITLE_MAX_LEN));
        SarifModel.SarifText fullDescription = new SarifModel.SarifText(nonBlank(f.description(), title));

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("tags", List.of("security", f.kind().wireValue()));
        if (f.cvss() != null && f.cvss().isKnown()) {
            properties.put("security-severity", String.format(Locale.ROOT, "%.1f", f.cvss().score()));
        }

        return new SarifModel.SarifRule(ruleId, ruleId, shortDescription, fullDescription, properties);
    }

    // --- result ---

    private static SarifModel.SarifResult buildResult(Finding f, String ruleId, int ruleIndex) {
        SarifModel.SarifText message = new SarifModel.SarifText(message(f));
        List<SarifModel.SarifLocation> locations = List.of(location(f));
        Map<String, String> fingerprints = Map.of("reachlayerFindingId/v1", f.id());

        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("source", f.source());
        properties.put("severity", f.severity());
        properties.put("reachability", f.reachability().wireValue());
        properties.put("kev", f.kev());
        if (!f.cve().isEmpty()) {
            properties.put("cve", f.cve());
        }
        if (!f.cwe().isEmpty()) {
            properties.put("cwe", f.cwe());
        }
        if (f.riskScore() != null) {
            properties.put("riskScore", f.riskScore());
        }
        if (isSyntheticLocation(f)) {
            properties.put("reachlayerSyntheticLocation", true);
        }

        return new SarifModel.SarifResult(ruleId, ruleIndex, level(f), message, locations, fingerprints, properties);
    }

    static String level(Finding f) {
        Double score = f.riskScore();
        if (score != null) {
            if (score >= ERROR_THRESHOLD) {
                return "error";
            }
            if (score >= WARNING_THRESHOLD) {
                return "warning";
            }
            return "note";
        }
        String sev = f.severity() == null ? "" : f.severity().toLowerCase(Locale.ROOT);
        return switch (sev) {
            case "critical", "high" -> "error";
            case "medium", "moderate" -> "warning";
            default -> "note";
        };
    }

    static String message(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append(nonBlank(f.title(), "(untitled finding)"));
        if (f.description() != null && !f.description().isBlank()) {
            sb.append(" — ").append(f.description());
        }
        sb.append(" [risk score: ")
                .append(f.riskScore() == null ? "not scored" : String.format(Locale.ROOT, "%.1f", f.riskScore()) + "/100")
                .append("; reachability: ")
                .append(f.reachability().wireValue());
        if (f.reachEvidence() != null && !f.reachEvidence().isBlank()) {
            sb.append(" (").append(f.reachEvidence()).append(")");
        }
        sb.append("]");
        if (f.riskExplanation() != null) {
            String rendered = f.riskExplanation().render();
            if (!rendered.isBlank()) {
                sb.append(" Why: ").append(rendered).append(".");
            }
        }
        String fix = (f.fixSuggestion() != null
                        && f.fixSuggestion().text() != null
                        && !f.fixSuggestion().text().isBlank())
                ? f.fixSuggestion().text()
                : "no fix suggestion available";
        sb.append(" Fix: ").append(fix);
        return sb.toString();
    }

    static SarifModel.SarifLocation location(Finding f) {
        Location loc = f.location();
        String uri;
        Integer startLine = null;
        Integer endLine = null;

        if (loc != null && loc.file() != null && !loc.file().isBlank()) {
            uri = loc.file();
            startLine = loc.startLine();
            endLine = loc.endLine();
        } else if (f.component() != null) {
            uri = "dependencies/" + f.component().coordinate();
        } else {
            uri = "UNKNOWN_LOCATION";
        }

        SarifModel.SarifRegion region =
                startLine == null ? null : new SarifModel.SarifRegion(startLine, endLine != null ? endLine : startLine);
        SarifModel.SarifPhysicalLocation physical =
                new SarifModel.SarifPhysicalLocation(new SarifModel.SarifArtifactLocation(uri), region);
        return new SarifModel.SarifLocation(physical);
    }

    static boolean isSyntheticLocation(Finding f) {
        Location loc = f.location();
        return loc == null || loc.file() == null || loc.file().isBlank();
    }

    private static String nonBlank(String s, String fallback) {
        return s == null || s.isBlank() ? fallback : s;
    }

    private static String truncate(String s, int maxLen) {
        return s.length() <= maxLen ? s : s.substring(0, Math.max(0, maxLen - 3)) + "...";
    }
}
