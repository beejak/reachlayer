# SARIF Output Renderer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new, independent `output/sarif` Gradle module containing `SarifOutputRenderer implements OutputRenderer`, which serializes a `RankedReport` as a SARIF 2.1.0 JSON file; wire it additively into `cmd`'s `Main` CLI via a new `--sarif-out` flag and into `action.yml` via a new `sarif-out` input; document the follow-on `upload-sarif` workflow step. See `docs/superpowers/specs/2026-07-31-sarif-output-renderer-design.md` for full rationale — this plan implements that spec task-by-task.

**Architecture:** Three new classes in `output/sarif/src/main/java/dev/reachlayer/output/sarif/`: `SarifModel` (nested public records forming the SARIF 2.1.0 object graph, directly Jackson-serializable), `SarifReportBuilder` (pure static mapping `RankedReport -> SarifModel.SarifLog`, mirrors `output/api`'s `MarkdownReportFormatter` split of "pure formatting" vs. "I/O renderer"), and `SarifOutputRenderer` (owns the `ObjectMapper` + file write, wraps `IOException` as `OutputException`). `cmd/Main.java` grows one CLI option and one new constructor parameter on an existing package-private factory method.

**Tech Stack:** Java 21, Jackson `jackson-databind` (already a transitive/direct dependency elsewhere in the repo — see `output/github-pr/build.gradle.kts`), JUnit 5 + AssertJ (repo-wide standard), picocli (already a `cmd` dependency).

## Global Constraints

- No changes to `core`, `connectors`, `reachability`, `enrich`, `scoring`, `advisor`, `output/api`, or `output/github-pr` — every field/method this plan reads already exists with the signature shown in "Reference: exact signatures" below (verified by direct reading).
- No live network calls in any test — this feature is pure in-memory mapping + local file I/O; every test uses `@TempDir Path` for anything touching disk, exactly like `ConsoleOutputRendererTest`/`GitHubPrCommentRendererTest`.
- Never fail the build: `SarifOutputRenderer.render(...)` must only ever throw `OutputException` (never let an `IOException` escape unwrapped); `Orchestrator.renderAll(...)` already catches `OutputException | RuntimeException` per-renderer as an additional backstop — do not weaken or duplicate that catch here, just don't rely on it being the *only* safety net.
- `--sarif-out` follows the exact same "blank string ⇒ not provided, never an error" convention as `--out`/`--fortify`/`--blackduck` etc.
- Follow existing test conventions exactly: `@TempDir Path tempDir`, JUnit 5 `@Test`, AssertJ `assertThat`/`assertThatThrownBy`, no mocking framework — fakes/temp files at the true I/O boundary only.
- JSON structure assertions in tests use `com.fasterxml.jackson.databind.ObjectMapper#readTree(...)` + `JsonNode#at(String jsonPointer)` (JSON Pointer navigation) — no new test dependency needed, `jackson-databind` is already on the test classpath transitively via the module's own `implementation` dependency.

---

## Reference: exact signatures this plan wires together

Copied verbatim from the source files (all already exist, already compile, already have their own passing tests):

```java
// core/src/main/java/dev/reachlayer/core/spi/OutputRenderer.java
public interface OutputRenderer {
    String name();
    void render(RankedReport report) throws OutputException;
}

// core/src/main/java/dev/reachlayer/core/spi/OutputException.java
public class OutputException extends Exception {
    public OutputException(String message);
    public OutputException(String message, Throwable cause);
}

// core/src/main/java/dev/reachlayer/core/model/RankedReport.java
public record RankedReport(List<Finding> findings, String repo, Instant generatedAt, int topN)
public static RankedReport of(List<Finding> findings, String repo, int topN)
public List<Finding> top()   // findings.subList(0, topN) or all if fewer
public List<Finding> rest()  // remainder

// core/src/main/java/dev/reachlayer/core/model/Finding.java — accessors used
public String id();
public String source();               // e.g. "fortify" | "blackduck"
public FindingKind kind();             // SAST | SCA — .wireValue() -> "sast"/"sca"
public List<String> cve();             // never null, may be empty
public List<String> cwe();             // never null, may be empty
public Component component();          // nullable
public Location location();            // never null; fields inside may be null
public String severity();              // never null, defaults "unknown"
public Cvss cvss();                    // never null, Cvss.UNKNOWN if absent
public String title();                 // nullable
public String description();           // nullable
public Reachability reachability();    // never null, defaults UNKNOWN — .wireValue()
public String reachEvidence();         // never null, defaults "not analyzed"
public Epss epss();                    // nullable
public boolean kev();
public BlastRadius blastRadius();      // never null, defaults BlastRadius.NONE
public Double riskScore();             // nullable
public RiskExplanation riskExplanation(); // nullable — .render() -> "factor: value; factor2: value2"
public FixSuggestion fixSuggestion();  // nullable — .text()

// core/src/main/java/dev/reachlayer/core/model/Location.java
public record Location(String file, Integer startLine, Integer endLine, String methodSignature)
public static Location unknown() // all-null

// core/src/main/java/dev/reachlayer/core/model/Component.java
public record Component(String name, String version, String ecosystem) {
    public String coordinate(); // "name@version" or "name"
}

// core/src/main/java/dev/reachlayer/core/model/Cvss.java
public record Cvss(Double score, String vector) {
    public boolean isKnown(); // score != null
}
public static final Cvss UNKNOWN;

// output/github-pr/build.gradle.kts — dependency shape to mirror (minus output:api)
val jacksonVersion: String by rootProject.extra
dependencies {
    implementation(project(":core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}

// cmd/src/main/java/dev/reachlayer/cli/Main.java — method this plan extends
static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment)
// current body: always adds ConsoleOutputRenderer(System.out, outFile); conditionally adds
// GitHubPrCommentRenderer.fromEnvironment(...) inside try/catch(IllegalStateException)

// cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java — existing call site to update
List<OutputRenderer> outputRenderers = Main.buildOutputRenderers(outFile, false); // 2-arg, becomes 3-arg
```

`settings.gradle.kts`'s `include(...)` block currently lists every module explicitly (no
`"output:sarif"` entry yet — added in Task 1). `cmd/build.gradle.kts` currently depends on
`project(":output:api")` and `project(":output:github-pr")` (no `:output:sarif"` yet — added in
Task 3).

---

### Task 1: SARIF model + pure report-to-SARIF mapping (`SarifModel`, `SarifReportBuilder`)

**Files:**
- Create: `output/sarif/build.gradle.kts`
- Modify: `settings.gradle.kts` (add `"output:sarif"` to `include(...)`)
- Create: `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifModel.java`
- Create: `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifReportBuilder.java`
- Test: `output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifReportBuilderTest.java`

**Interfaces:**
- Consumes: `RankedReport`, `Finding` and all its accessors listed in "Reference" above.
- Produces: `public static SarifModel.SarifLog SarifReportBuilder.build(RankedReport report)` — a
  pure function, no I/O, used directly by Task 2's `SarifOutputRenderer` and by this task's test.

- [ ] **Step 1: Scaffold the module**

Create `output/sarif/build.gradle.kts`:

```kotlin
val jacksonVersion: String by rootProject.extra

dependencies {
    implementation(project(":core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}
```

Modify `settings.gradle.kts` — add `"output:sarif"` right after `"output:github-pr"`:

```kotlin
include(
    "core",
    "connectors:api",
    "connectors:fortify",
    "connectors:blackduck",
    "reachability",
    "enrich:epss",
    "enrich:kev",
    "enrich:blastradius",
    "scoring",
    "advisor:api",
    "advisor:providers:noop",
    "advisor:providers:anthropic",
    "output:api",
    "output:github-pr",
    "output:sarif",
    "cmd",
    "fixtures:vulnerable-spring-app",
)
```

- [ ] **Step 2: Write the failing test**

Create `output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifReportBuilderTest.java`:

```java
package dev.reachlayer.output.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.model.RiskExplanation;
import dev.reachlayer.core.model.FixSuggestion;
import java.util.List;
import org.junit.jupiter.api.Test;

class SarifReportBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode toJson(SarifModel.SarifLog log) throws Exception {
        return MAPPER.readTree(MAPPER.writeValueAsString(log));
    }

    @Test
    void mapsFullyPopulatedSastFindingToRuleAndResult() throws Exception {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .cwe(List.of("CWE-89"))
                .title("SQL Injection")
                .description("Untrusted input flows into a SQL query.")
                .location(new Location("src/main/java/App.java", 42, 44, "App#handle"))
                .severity("High")
                .cvss(new Cvss(9.1, "CVSS:3.1/..."))
                .reachability(Reachability.REACHABLE)
                .reachEvidence("main -> App#handle -> Dao#query")
                .riskScore(92.0)
                .riskExplanation(RiskExplanation.builder().add("base", "0.9").add("reachable", "1.0").build())
                .fixSuggestion(FixSuggestion.template(FixSuggestion.Type.CODE_FIX, "Use a parameterized query."))
                .build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)));

        assertThat(json.at("/version").asText()).isEqualTo("2.1.0");
        assertThat(json.at("/$schema").asText()).contains("sarif-schema-2.1.0.json");
        assertThat(json.at("/runs/0/tool/driver/name").asText()).isEqualTo("Reachlayer");
        assertThat(json.at("/runs/0/tool/driver/rules").size()).isEqualTo(1);
        assertThat(json.at("/runs/0/tool/driver/rules/0/id").asText()).isEqualTo("fortify:CWE-89");

        JsonNode result = json.at("/runs/0/results/0");
        assertThat(result.at("/ruleId").asText()).isEqualTo("fortify:CWE-89");
        assertThat(result.at("/ruleIndex").asInt()).isEqualTo(0);
        assertThat(result.at("/level").asText()).isEqualTo("error"); // riskScore 92 >= 75
        assertThat(result.at("/message/text").asText())
                .contains("92.0/100")
                .contains("reachable")
                .contains("Use a parameterized query.");
        assertThat(result.at("/locations/0/physicalLocation/artifactLocation/uri").asText())
                .isEqualTo("src/main/java/App.java");
        assertThat(result.at("/locations/0/physicalLocation/region/startLine").asInt()).isEqualTo(42);
        assertThat(result.at("/locations/0/physicalLocation/region/endLine").asInt()).isEqualTo(44);
        assertThat(result.at("/partialFingerprints/reachlayerFindingId~1v1").asText()).isEqualTo("f1");
    }

    @Test
    void scaFindingWithNoLocationGetsSyntheticDependencyLocationAndFlag() throws Exception {
        Finding finding = Finding.builder()
                .id("f2")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .cve(List.of("CVE-2021-44228"))
                .component(Component.of("org.apache.logging.log4j:log4j-core", "2.14.1"))
                .title("Remote code execution in Log4j")
                .build();

        JsonNode result = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)))
                .at("/runs/0/results/0");

        String uri = result.at("/locations/0/physicalLocation/artifactLocation/uri").asText();
        assertThat(uri).startsWith("dependencies/").contains("log4j-core@2.14.1");
        assertThat(result.at("/properties/reachlayerSyntheticLocation").asBoolean()).isTrue();
        assertThat(result.at("/locations/0/physicalLocation/region").isMissingNode()).isTrue();
    }

    @Test
    void findingWithNoCweOrCveFallsBackToSlugifiedTitleForRuleId() throws Exception {
        Finding finding = Finding.builder()
                .id("f3")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Hardcoded Password!!")
                .build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(finding), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo("fortify:hardcoded-password");
    }

    @Test
    void distinctFindingsSharingTheSameCweShareOneRuleButProduceTwoResults() throws Exception {
        Finding f1 = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST)
                .cwe(List.of("CWE-89")).title("SQLi A").build();
        Finding f2 = Finding.builder().id("f2").source("fortify").kind(FindingKind.SAST)
                .cwe(List.of("CWE-89")).title("SQLi B").build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(f1, f2), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/tool/driver/rules").size()).isEqualTo(1);
        assertThat(json.at("/runs/0/results").size()).isEqualTo(2);
        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo(json.at("/runs/0/results/1/ruleId").asText());
        assertThat(json.at("/runs/0/results/0/ruleIndex").asInt()).isEqualTo(0);
        assertThat(json.at("/runs/0/results/1/ruleIndex").asInt()).isEqualTo(0);
    }

    @Test
    void neverThrowsOnSparselyPopulatedFinding() {
        Finding bare = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();
        RankedReport report = RankedReport.of(List.of(bare), "acme/widgets", 5);

        assertThatCode(() -> SarifReportBuilder.build(report)).doesNotThrowAnyException();
    }

    @Test
    void sparselyPopulatedFindingMessageDegradesGracefully() throws Exception {
        Finding bare = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        JsonNode result = toJson(SarifReportBuilder.build(RankedReport.of(List.of(bare), "acme/widgets", 5)))
                .at("/runs/0/results/0");

        assertThat(result.at("/message/text").asText())
                .contains("not scored")
                .contains("no fix suggestion available");
        assertThat(result.at("/level").asText()).isEqualTo("note"); // unknown severity, no riskScore -> conservative default
    }

    @Test
    void levelMappingBucketsRiskScoreIntoErrorWarningNote() throws Exception {
        Finding high = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).riskScore(80.0).build();
        Finding mid = Finding.builder().id("f2").source("fortify").kind(FindingKind.SAST).riskScore(50.0).build();
        Finding low = Finding.builder().id("f3").source("fortify").kind(FindingKind.SAST).riskScore(10.0).build();

        JsonNode json = toJson(SarifReportBuilder.build(RankedReport.of(List.of(high, mid, low), "acme/widgets", 5)));

        assertThat(json.at("/runs/0/results/0/level").asText()).isEqualTo("error");
        assertThat(json.at("/runs/0/results/1/level").asText()).isEqualTo("warning");
        assertThat(json.at("/runs/0/results/2/level").asText()).isEqualTo("note");
    }
}
```

Note: JSON Pointer (`JsonNode#at`) escapes `/` as `~1` and `~` as `~0` inside a segment — the
`partialFingerprints` key `"reachlayerFindingId/v1"` is addressed above as
`/partialFingerprints/reachlayerFindingId~1v1`. Keep that escaping if you copy this test verbatim;
it is correct as written, not a typo.

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew.bat :output:sarif:compileTestJava`
Expected: FAIL — compile error, `SarifModel`/`SarifReportBuilder` do not exist yet.

- [ ] **Step 4: Write minimal implementation**

Create `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifModel.java`:

```java
package dev.reachlayer.output.sarif;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * A minimal SARIF 2.1.0 object graph — only the properties GitHub's code-scanning SARIF ingestion
 * (and most other SARIF consumers) actually read. Every record here serializes directly via
 * Jackson's native record support (no annotations needed except {@code $schema}, which isn't a
 * legal Java identifier). See the design spec for the exact field-by-field mapping rationale.
 */
public final class SarifModel {

    private SarifModel() {
    }

    public record SarifLog(@JsonProperty("$schema") String schema, String version, List<SarifRun> runs) {
    }

    public record SarifRun(SarifTool tool, List<SarifResult> results) {
    }

    public record SarifTool(SarifDriver driver) {
    }

    public record SarifDriver(String name, String informationUri, String version, List<SarifRule> rules) {
    }

    public record SarifRule(
            String id, String name, SarifText shortDescription, SarifText fullDescription, Map<String, Object> properties) {
    }

    public record SarifText(String text) {
    }

    public record SarifResult(
            String ruleId,
            int ruleIndex,
            String level,
            SarifText message,
            List<SarifLocation> locations,
            Map<String, String> partialFingerprints,
            Map<String, Object> properties) {
    }

    public record SarifLocation(SarifPhysicalLocation physicalLocation) {
    }

    public record SarifPhysicalLocation(SarifArtifactLocation artifactLocation, SarifRegion region) {
    }

    public record SarifArtifactLocation(String uri) {
    }

    public record SarifRegion(Integer startLine, Integer endLine) {
    }
}
```

Create `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifReportBuilder.java`:

```java
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew.bat :output:sarif:test --tests "dev.reachlayer.output.sarif.SarifReportBuilderTest"`
Expected: PASS, 7 tests.

- [ ] **Step 6: Commit**

```bash
git add settings.gradle.kts output/sarif/build.gradle.kts output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifModel.java output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifReportBuilder.java output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifReportBuilderTest.java
git commit -m "feat(output-sarif): add SARIF 2.1.0 model and RankedReport mapping"
```

---

### Task 2: `SarifOutputRenderer` — the `OutputRenderer` implementation (I/O boundary)

**Files:**
- Create: `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifOutputRenderer.java`
- Test: `output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifOutputRendererTest.java`

**Interfaces:**
- Consumes: `SarifReportBuilder.build(RankedReport)` from Task 1; `OutputRenderer`, `OutputException` from `core`.
- Produces: `public final class SarifOutputRenderer implements OutputRenderer` with
  `SarifOutputRenderer(Path outputFile)` and `SarifOutputRenderer(Path outputFile, ObjectMapper mapper)`
  constructors (the second exists purely for test injection, same shape as
  `GitHubPrCommentRenderer`'s two-constructor pattern). Task 3 (`Main`) uses the single-arg
  constructor.

- [ ] **Step 1: Write the failing test**

Create `output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifOutputRendererTest.java`:

```java
package dev.reachlayer.output.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SarifOutputRendererTest {

    private static RankedReport sampleReport() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Sample finding")
                .severity("High")
                .riskScore(80.0)
                .build();
        return RankedReport.of(List.of(finding), "acme/widgets", 5);
    }

    @Test
    void nameIsSarif() {
        SarifOutputRenderer renderer = new SarifOutputRenderer(Path.of("unused.sarif"));
        assertThat(renderer.name()).isEqualTo("sarif");
    }

    @Test
    void writesValidSarifJsonToGivenPath(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        renderer.render(sampleReport());

        assertThat(Files.exists(outputFile)).isTrue();
        JsonNode json = new ObjectMapper().readTree(Files.readString(outputFile));
        assertThat(json.at("/version").asText()).isEqualTo("2.1.0");
        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo("fortify:sample-finding");
    }

    @Test
    void createsParentDirectoriesIfMissing(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("nested/dir/report.sarif");
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        renderer.render(sampleReport());

        assertThat(Files.exists(outputFile)).isTrue();
    }

    @Test
    void omitsNullFieldsLikeRegionWhenLocationHasNoLineNumber(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        new SarifOutputRenderer(outputFile).render(sampleReport());

        String raw = Files.readString(outputFile);
        assertThat(raw).doesNotContain("\"region\" : null");
        assertThat(raw).doesNotContain("\"region\":null");
    }

    @Test
    void wrapsIoFailureAsOutputException(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        Files.createDirectory(outputFile); // a directory already occupies this path -> write must fail
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        assertThatThrownBy(() -> renderer.render(sampleReport()))
                .isInstanceOf(OutputException.class)
                .hasMessageContaining(outputFile.toString())
                .hasCauseInstanceOf(java.io.IOException.class);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew.bat :output:sarif:compileTestJava`
Expected: FAIL — compile error, `SarifOutputRenderer` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifOutputRenderer.java`:

```java
package dev.reachlayer.output.sarif;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Writes a {@link RankedReport} as a SARIF 2.1.0 JSON file to {@code outputFile}, for later
 * upload via a {@code github/codeql-action/upload-sarif} workflow step (Reachlayer itself never
 * calls GitHub's upload API — see {@code docs/sarif-output.md}). Mapping is delegated entirely to
 * {@link SarifReportBuilder}; this class owns only the {@link ObjectMapper} configuration and the
 * file write, wrapping any {@link IOException} as an {@link OutputException} per the {@link
 * OutputRenderer} contract — this renderer must never fail the build.
 */
public final class SarifOutputRenderer implements OutputRenderer {

    private final Path outputFile;
    private final ObjectMapper mapper;

    public SarifOutputRenderer(Path outputFile) {
        this(outputFile, defaultMapper());
    }

    /** Package-visible-for-tests-friendly overload; also usable by callers with their own mapper config. */
    public SarifOutputRenderer(Path outputFile, ObjectMapper mapper) {
        this.outputFile = Objects.requireNonNull(outputFile, "outputFile");
        this.mapper = mapper == null ? defaultMapper() : mapper;
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public String name() {
        return "sarif";
    }

    @Override
    public void render(RankedReport report) throws OutputException {
        SarifModel.SarifLog log = SarifReportBuilder.build(report);
        try {
            Path parent = outputFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile.toFile(), log);
        } catch (IOException e) {
            throw new OutputException("Failed to write SARIF report to " + outputFile, e);
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew.bat :output:sarif:test`
Expected: PASS, all tests in both `SarifReportBuilderTest` (7) and `SarifOutputRendererTest` (5).

- [ ] **Step 5: Commit**

```bash
git add output/sarif/src/main/java/dev/reachlayer/output/sarif/SarifOutputRenderer.java output/sarif/src/test/java/dev/reachlayer/output/sarif/SarifOutputRendererTest.java
git commit -m "feat(output-sarif): add SarifOutputRenderer writing SARIF files to disk"
```

---

### Task 3: Wire `--sarif-out` into `cmd/Main.java`

**Files:**
- Modify: `cmd/build.gradle.kts` (add `implementation(project(":output:sarif"))`)
- Modify: `cmd/src/main/java/dev/reachlayer/cli/Main.java`
- Modify: `cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java`

**Interfaces:**
- Consumes: `SarifOutputRenderer(Path)` from Task 2.
- Produces: extended `static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment, Path sarifOutFile)` (3-arg, was 2-arg).

- [ ] **Step 1: Add the module dependency**

Modify `cmd/build.gradle.kts` — add one line after the `:output:github-pr` dependency:

```kotlin
    implementation(project(":output:api"))
    implementation(project(":output:github-pr"))
    implementation(project(":output:sarif"))
```

- [ ] **Step 2: Write the failing test (extend `MainWiringIT`)**

Modify `cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java`:

1. Add an import: `import dev.reachlayer.output.sarif.SarifOutputRenderer;`
2. Change the existing call site inside `runsFullPipelineAgainstRealFixturesAndProducesAScoredRenderedReport(...)` from:

```java
        Path outFile = tempDir.resolve("report.md");
        List<OutputRenderer> outputRenderers = Main.buildOutputRenderers(outFile, false); // no GitHub env vars in CI
```

to:

```java
        Path outFile = tempDir.resolve("report.md");
        Path sarifOutFile = tempDir.resolve("report.sarif");
        List<OutputRenderer> outputRenderers =
                Main.buildOutputRenderers(outFile, false, sarifOutFile); // no GitHub env vars in CI
```

3. Append assertions at the end of that same test (after the existing `assertThat(written).contains(...)` lines):

```java
        assertThat(sarifOutFile).exists();
        String sarifJson = Files.readString(sarifOutFile);
        assertThat(sarifJson).contains("\"version\" : \"2.1.0\"");
        assertThat(sarifJson).contains("CVE-2021-44228"); // at least one of the 3 Black Duck CVEs surfaces in properties
```

4. Add a new standalone test method:

```java
    @Test
    void buildOutputRenderersAddsSarifRendererOnlyWhenPathProvided(@TempDir Path tempDir) {
        List<OutputRenderer> withSarif =
                Main.buildOutputRenderers(null, false, tempDir.resolve("out.sarif"));
        assertThat(withSarif).anyMatch(r -> r instanceof SarifOutputRenderer);

        List<OutputRenderer> withoutSarif = Main.buildOutputRenderers(null, false, null);
        assertThat(withoutSarif).noneMatch(r -> r instanceof SarifOutputRenderer);
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew.bat :cmd:compileTestJava`
Expected: FAIL — compile error, `Main.buildOutputRenderers` still takes 2 args, no 3-arg overload exists yet.

- [ ] **Step 4: Update `Main.java`**

Modify `cmd/src/main/java/dev/reachlayer/cli/Main.java`:

1. Add the import (alongside the existing `output.*` imports):

```java
import dev.reachlayer.output.sarif.SarifOutputRenderer;
```

2. Add a new `@Option` field, right after the existing `--out` option:

```java
    @Option(names = "--out", defaultValue = "", description = "Path to also write the rendered Markdown report to.")
    private String out;

    @Option(
            names = "--sarif-out",
            defaultValue = "",
            description = "Path to also write a SARIF 2.1.0 report to (for GitHub code scanning upload).")
    private String sarifOut;
```

3. In `runPipeline()`, change:

```java
        List<OutputRenderer> outputRenderers =
                buildOutputRenderers(out.isBlank() ? null : Path.of(out), postPrComment);
```

to:

```java
        List<OutputRenderer> outputRenderers = buildOutputRenderers(
                out.isBlank() ? null : Path.of(out),
                postPrComment,
                sarifOut.isBlank() ? null : Path.of(sarifOut));
```

4. Change `buildOutputRenderers` itself from:

```java
    static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment) {
        List<OutputRenderer> renderers = new ArrayList<>();
        renderers.add(new ConsoleOutputRenderer(System.out, outFile));
        if (attemptPrComment) {
            try {
                renderers.add(GitHubPrCommentRenderer.fromEnvironment(GitHubRestApiClient.fromEnvironment()));
            } catch (IllegalStateException e) {
                log.info("Skipping GitHub PR comment rendering: {}", e.getMessage());
            }
        }
        return renderers;
    }
```

to:

```java
    static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment, Path sarifOutFile) {
        List<OutputRenderer> renderers = new ArrayList<>();
        renderers.add(new ConsoleOutputRenderer(System.out, outFile));
        if (sarifOutFile != null) {
            renderers.add(new SarifOutputRenderer(sarifOutFile));
        }
        if (attemptPrComment) {
            try {
                renderers.add(GitHubPrCommentRenderer.fromEnvironment(GitHubRestApiClient.fromEnvironment()));
            } catch (IllegalStateException e) {
                log.info("Skipping GitHub PR comment rendering: {}", e.getMessage());
            }
        }
        return renderers;
    }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew.bat :cmd:test --tests "dev.reachlayer.cli.MainWiringIT"`
Expected: PASS, 5 tests (the original 4 plus the new `buildOutputRenderersAddsSarifRendererOnlyWhenPathProvided`).

- [ ] **Step 6: Run the full `cmd` test suite**

Run: `./gradlew.bat :cmd:test`
Expected: BUILD SUCCESSFUL — `EnrichmentPipelineTest` and `MainWiringIT` both pass.

- [ ] **Step 7: Commit**

```bash
git add cmd/build.gradle.kts cmd/src/main/java/dev/reachlayer/cli/Main.java cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java
git commit -m "feat(cmd): wire --sarif-out into Main and buildOutputRenderers"
```

---

### Task 4: `action.yml` input/output + docs (`docs/sarif-output.md`, `docs/architecture.md`, `PLAN.md`)

**Files:**
- Modify: `action.yml`
- Create: `docs/sarif-output.md`
- Modify: `docs/architecture.md`
- Modify: `PLAN.md`

**Interfaces:** none — documentation and Action-metadata only, no code.

- [ ] **Step 1: Add the `sarif-out` input and output to `action.yml`**

Modify `action.yml`:

Add to `inputs:` (after `post-pr-comment`):

```yaml
  sarif-out:
    description: >-
      Optional path to also write a SARIF 2.1.0 report to inside the action's workspace (for a
      later github/codeql-action/upload-sarif step in the consumer's own workflow). Blank skips
      SARIF output entirely.
    required: false
    default: ""
```

Add to `outputs:` (after `report-path`):

```yaml
  sarif-path:
    description: "Path to the rendered SARIF report inside the action's workspace, when sarif-out is set."
```

Add to the Docker `args:` list (after `--out=...`):

```yaml
    - "--sarif-out=${{ inputs.sarif-out }}"
```

- [ ] **Step 2: Write `docs/sarif-output.md`**

Create `docs/sarif-output.md`:

```markdown
# SARIF output

`output/sarif`'s `SarifOutputRenderer` writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
JSON file summarizing every finding in a `RankedReport` — the same static-analysis interchange
format GitHub's code-scanning feature consumes.

Reachlayer's job stops at writing that file to disk. It does **not** call GitHub's SARIF upload
API itself (that would duplicate an Action GitHub already publishes and maintains, and would be
scope creep beyond "render SARIF"). To get GitHub code-scanning annotations from the file
Reachlayer produces, add one more step to your workflow after the Reachlayer Action step:

```yaml
- uses: reachlayer/reachlayer@v0
  with:
    fortify-fvdl: audit.fvdl
    blackduck-bdio: scan.json
    sarif-out: reachlayer-report.sarif
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reachlayer-report.sarif
```

Or from the standalone CLI:

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --sarif-out reachlayer-report.sarif
```

This, like every other `OutputRenderer`, is strictly additive/advisory — GitHub code-scanning
annotations from an uploaded SARIF file do not fail a build any more than the PR comment does; see
`PLAN.md` principle 1.

## Mapping notes

- One SARIF *rule* per distinct `{source}:{CWE-or-CVE-or-slugified-title}` — repeated instances of
  the same underlying issue across files are grouped under one rule, not duplicated.
- `message.text` always includes the risk score, reachability tag, and fix suggestion.
- SCA findings that lack a file/line (the common case — Black Duck findings are usually
  component-level) get a synthetic `dependencies/<coordinate>` location, flagged
  `reachlayerSyntheticLocation: true` in the result's `properties`, rather than being omitted.

See `docs/superpowers/specs/2026-07-31-sarif-output-renderer-design.md` for the full design
rationale.
```

- [ ] **Step 3: Update `docs/architecture.md`**

Modify the module table row in `docs/architecture.md` from:

```markdown
| `output:api`, `:github-pr` | `dev.reachlayer.output.*` | `OutputRenderer` SPI; Markdown formatting; single-comment GitHub PR upsert. |
```

to:

```markdown
| `output:api`, `:github-pr`, `:sarif` | `dev.reachlayer.output.*` | `OutputRenderer` SPI; Markdown formatting; single-comment GitHub PR upsert; SARIF 2.1.0 report for GitHub code scanning (see `docs/sarif-output.md`). |
```

- [ ] **Step 4: Update `PLAN.md`'s Phase 1 bullet**

Modify `PLAN.md`'s Phase 1 section from:

```markdown
- **SARIF output renderer** (GitHub code-scanning annotations, still non-blocking).
```

to:

```markdown
- **SARIF output renderer** (GitHub code-scanning annotations, still non-blocking) — implemented:
  `output/sarif`'s `SarifOutputRenderer`, wired via `cmd`'s `--sarif-out` flag / `action.yml`'s
  `sarif-out` input. See `docs/sarif-output.md`.
```

- [ ] **Step 5: Commit**

```bash
git add action.yml docs/sarif-output.md docs/architecture.md PLAN.md
git commit -m "docs: document SARIF output renderer and action.yml sarif-out input"
```

---

### Task 5: Full build verification and one manual end-to-end run

**Files:** none created; this task runs the built artifact, it does not add code.

- [ ] **Step 1: Run the full repo build**

Run: `./gradlew.bat build` (from repo root)
Expected: BUILD SUCCESSFUL — every module's tests pass, including the two new `output:sarif` test
classes and `cmd`'s updated `MainWiringIT`.

- [ ] **Step 2: Run the CLI once against the real fixtures, with `--sarif-out` set**

Run (from repo root):

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --out reachlayer-report.md \
  --sarif-out reachlayer-report.sarif
```

Expected: exits `0`; both `reachlayer-report.md` and `reachlayer-report.sarif` are created in the
repo root.

- [ ] **Step 3: Inspect the generated SARIF file**

Run: `cat reachlayer-report.sarif` (or open it)
Expected: valid JSON; `"version": "2.1.0"`; `runs[0].tool.driver.rules` contains one rule per
distinct CWE/CVE/title-slug among the 5 fixture findings; `runs[0].results` has 5 entries; at least
one SCA result's `locations[0].physicalLocation.artifactLocation.uri` starts with `dependencies/`
and its `properties.reachlayerSyntheticLocation` is `true`.

- [ ] **Step 4: Sanity-check the file against a public SARIF viewer (optional but recommended)**

Paste the file's contents into https://microsoft.github.io/sarif-web-component/ (or any SARIF
viewer) and confirm it renders without a parse/schema error.

- [ ] **Step 5: Clean up the manual run's output files**

Run: `rm reachlayer-report.md reachlayer-report.sarif` (manual verification artifacts, not repo
files — do not commit them).

- [ ] **Step 6: Final full-suite confirmation**

Run: `./gradlew.bat build`
Expected: BUILD SUCCESSFUL (repeat of Step 1, run once more after cleanup to confirm nothing in
Steps 2-5 left the repo in a state that breaks the build — e.g. stray generated files accidentally
picked up by a module's resource set).

---

## Self-review notes (completed during planning, not a task to execute)

- **Spec coverage:** every section of the design spec maps to a task — SARIF schema mapping
  (rule-id scheme, level mapping, location fallback, message composition) → Task 1; non-blocking
  I/O guarantee → Task 2; `cmd`/`action.yml` wiring → Tasks 3-4; the "no uploader, that's a
  separate Action" non-goal → documented in `docs/sarif-output.md` (Task 4), not built anywhere.
- **Placeholder scan:** no `TODO`/`FIXME`/stub method bodies left in any task's code blocks above;
  every helper method (`ruleId`, `slug`, `level`, `message`, `location`, `isSyntheticLocation`) is
  fully implemented, not sketched.
- **Type consistency:** `SarifOutputRenderer(Path)` in Task 2 exactly matches its use in `Main`'s
  `buildOutputRenderers` in Task 3; `buildOutputRenderers`'s 3-arg signature in Task 3 exactly
  matches both call sites updated in `MainWiringIT` (the extended existing test and the new
  standalone test).
- **Pre-existing gap flagged, not silently fixed:** `action.yml`'s `report-path` output was already
  declared-but-unwired before this plan (no code anywhere calls `$GITHUB_OUTPUT`); `sarif-path` is
  added in the same (currently unwired) state for consistency, and this is called out explicitly
  in the spec's Non-goals rather than either quietly fixed (scope creep) or silently left
  inconsistent (one output wired, one not).
- **Dockerfile:** confirmed no change needed — `COPY output ./output` in `Dockerfile` already
  copies the whole `output/` directory tree, which will include the new `output/sarif` subproject
  automatically once it exists on disk.
- **JSON Pointer escaping in Task 1's test:** double-checked that `/partialFingerprints/reachlayerFindingId~1v1`
  is the correct RFC 6901 escaping of the literal map key `"reachlayerFindingId/v1"` (`/` → `~1`)
  — flagged inline in the test itself so a future editor copying this test doesn't "fix" it into a
  broken pointer.
