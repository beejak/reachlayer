package dev.reachlayer.core.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The canonical finding model — the contract every {@code ScannerConnector} emits and every
 * pipeline stage progressively enriches. See PLAN.md §3.3.
 *
 * <p>Immutable. Each pipeline stage (reachability, enrich, scoring, advisor) produces a new
 * {@code Finding} via {@link #toBuilder()} rather than mutating in place, so earlier stages can
 * never be surprised by later ones and the pipeline is trivially testable stage-by-stage.
 */
public final class Finding {

    // --- fields every connector sets ---
    private final String id;
    private final String source;
    private final FindingKind kind;
    private final List<String> cve;
    private final List<String> cwe;
    private final Component component;
    private final Location location;
    private final String severity;
    private final Cvss cvss;
    private final Map<String, String> rawScannerFields;
    private final String title;
    private final String description;

    // --- fields Reachlayer adds, progressively ---
    private final Reachability reachability;
    private final String reachEvidence;
    private final Reachability vendorReachability;
    private final Epss epss;
    private final boolean kev;
    private final BlastRadius blastRadius;
    private final Double riskScore;
    private final RiskExplanation riskExplanation;
    private final FixSuggestion fixSuggestion;
    private final Boolean isNew;

    private Finding(Builder b) {
        this.id = Objects.requireNonNull(b.id, "id");
        this.source = Objects.requireNonNull(b.source, "source");
        this.kind = Objects.requireNonNull(b.kind, "kind");
        this.cve = List.copyOf(b.cve);
        this.cwe = List.copyOf(b.cwe);
        this.component = b.component;
        this.location = b.location == null ? Location.unknown() : b.location;
        this.severity = b.severity == null ? "unknown" : b.severity;
        this.cvss = b.cvss == null ? Cvss.UNKNOWN : b.cvss;
        this.rawScannerFields = Map.copyOf(b.rawScannerFields);
        this.title = b.title;
        this.description = b.description;
        this.reachability = b.reachability == null ? Reachability.UNKNOWN : b.reachability;
        this.reachEvidence = b.reachEvidence == null ? "not analyzed" : b.reachEvidence;
        this.vendorReachability = b.vendorReachability;
        this.epss = b.epss;
        this.kev = b.kev;
        this.blastRadius = b.blastRadius == null ? BlastRadius.NONE : b.blastRadius;
        this.riskScore = b.riskScore;
        this.riskExplanation = b.riskExplanation;
        this.fixSuggestion = b.fixSuggestion;
        this.isNew = b.isNew;
    }

    public String id() {
        return id;
    }

    public String source() {
        return source;
    }

    public FindingKind kind() {
        return kind;
    }

    public List<String> cve() {
        return cve;
    }

    public List<String> cwe() {
        return cwe;
    }

    public Component component() {
        return component;
    }

    public Location location() {
        return location;
    }

    public String severity() {
        return severity;
    }

    public Cvss cvss() {
        return cvss;
    }

    public Map<String, String> rawScannerFields() {
        return rawScannerFields;
    }

    public String title() {
        return title;
    }

    public String description() {
        return description;
    }

    public Reachability reachability() {
        return reachability;
    }

    public String reachEvidence() {
        return reachEvidence;
    }

    /**
     * The scanner's own reachability/impact-analysis verdict, when its export carries one (e.g.
     * Black Duck Detect's "Vulnerability Impact Analysis" — see {@code docs/connectors.md}), as a
     * second signal alongside Reachlayer's own computed {@link #reachability()}. {@code null} when
     * the scanner didn't report one, which is the common case. Never used in place of Reachlayer's
     * own tag — see PLAN.md §2 principle 2, "layer, never replace" — only surfaced alongside it.
     */
    public Reachability vendorReachability() {
        return vendorReachability;
    }

    public Epss epss() {
        return epss;
    }

    public boolean kev() {
        return kev;
    }

    public BlastRadius blastRadius() {
        return blastRadius;
    }

    public Double riskScore() {
        return riskScore;
    }

    public RiskExplanation riskExplanation() {
        return riskExplanation;
    }

    public FixSuggestion fixSuggestion() {
        return fixSuggestion;
    }

    /**
     * Whether this finding is new relative to a baseline (PLAN.md §5 Phase 1, "baseline/diff
     * mode"): {@code null} when no baseline was used for this run (the default), {@code true}
     * when this finding's {@link #id()} was absent from the baseline (introduced since it was
     * captured), {@code false} when present in it (pre-existing). Set by {@code
     * core.baseline.BaselineDiffer} via {@code core.pipeline.BaselineStage}.
     */
    public Boolean isNew() {
        return isNew;
    }

    public Builder toBuilder() {
        Builder b = new Builder();
        b.id = id;
        b.source = source;
        b.kind = kind;
        b.cve = cve;
        b.cwe = cwe;
        b.component = component;
        b.location = location;
        b.severity = severity;
        b.cvss = cvss;
        b.rawScannerFields = rawScannerFields;
        b.title = title;
        b.description = description;
        b.reachability = reachability;
        b.reachEvidence = reachEvidence;
        b.vendorReachability = vendorReachability;
        b.epss = epss;
        b.kev = kev;
        b.blastRadius = blastRadius;
        b.riskScore = riskScore;
        b.riskExplanation = riskExplanation;
        b.fixSuggestion = fixSuggestion;
        b.isNew = isNew;
        return b;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Computes a stable id from source + rule/CWE + location + component, so the same finding
     * hashes the same way across runs (used for dedup and for PR-comment cache keys).
     */
    public static String stableId(String source, String rule, Location location, Component component) {
        String basis = String.join(
                "|",
                nullToEmpty(source),
                nullToEmpty(rule),
                location == null ? "" : nullToEmpty(location.file()) + ":" + location.startLine(),
                component == null ? "" : component.coordinate());
        return source + "-" + Integer.toHexString(basis.hashCode());
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Finding finding)) return false;
        return Objects.equals(id, finding.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }

    @Override
    public String toString() {
        return "Finding{id=%s, source=%s, kind=%s, severity=%s, reachability=%s, riskScore=%s}"
                .formatted(id, source, kind, severity, reachability, riskScore);
    }

    public static final class Builder {
        private String id;
        private String source;
        private FindingKind kind;
        private List<String> cve = List.of();
        private List<String> cwe = List.of();
        private Component component;
        private Location location;
        private String severity;
        private Cvss cvss;
        private Map<String, String> rawScannerFields = new LinkedHashMap<>();
        private String title;
        private String description;
        private Reachability reachability;
        private String reachEvidence;
        private Reachability vendorReachability;
        private Epss epss;
        private boolean kev;
        private BlastRadius blastRadius;
        private Double riskScore;
        private RiskExplanation riskExplanation;
        private FixSuggestion fixSuggestion;
        private Boolean isNew;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder source(String source) {
            this.source = source;
            return this;
        }

        public Builder kind(FindingKind kind) {
            this.kind = kind;
            return this;
        }

        public Builder cve(List<String> cve) {
            this.cve = cve == null ? List.of() : cve;
            return this;
        }

        public Builder cwe(List<String> cwe) {
            this.cwe = cwe == null ? List.of() : cwe;
            return this;
        }

        public Builder component(Component component) {
            this.component = component;
            return this;
        }

        public Builder location(Location location) {
            this.location = location;
            return this;
        }

        public Builder severity(String severity) {
            this.severity = severity;
            return this;
        }

        public Builder cvss(Cvss cvss) {
            this.cvss = cvss;
            return this;
        }

        public Builder rawScannerFields(Map<String, String> rawScannerFields) {
            this.rawScannerFields = rawScannerFields == null ? new LinkedHashMap<>() : rawScannerFields;
            return this;
        }

        /** No-op if {@code value} is {@code null} (raw fields are frequently absent from scanner output). */
        public Builder putRawField(String key, String value) {
            if (value != null) {
                this.rawScannerFields.put(key, value);
            }
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder reachability(Reachability reachability) {
            this.reachability = reachability;
            return this;
        }

        public Builder reachEvidence(String reachEvidence) {
            this.reachEvidence = reachEvidence;
            return this;
        }

        public Builder vendorReachability(Reachability vendorReachability) {
            this.vendorReachability = vendorReachability;
            return this;
        }

        public Builder epss(Epss epss) {
            this.epss = epss;
            return this;
        }

        public Builder kev(boolean kev) {
            this.kev = kev;
            return this;
        }

        public Builder blastRadius(BlastRadius blastRadius) {
            this.blastRadius = blastRadius;
            return this;
        }

        public Builder riskScore(Double riskScore) {
            this.riskScore = riskScore;
            return this;
        }

        public Builder riskExplanation(RiskExplanation riskExplanation) {
            this.riskExplanation = riskExplanation;
            return this;
        }

        public Builder fixSuggestion(FixSuggestion fixSuggestion) {
            this.fixSuggestion = fixSuggestion;
            return this;
        }

        public Builder isNew(Boolean isNew) {
            this.isNew = isNew;
            return this;
        }

        public Finding build() {
            return new Finding(this);
        }
    }
}
