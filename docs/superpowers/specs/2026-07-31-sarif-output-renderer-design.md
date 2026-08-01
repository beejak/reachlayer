# SARIF output renderer — design spec

**Date:** 2026-07-31
**Status:** proposed, proceeding to implementation plan

## Context

`PLAN.md` §5 Phase 1 lists "SARIF output renderer (GitHub code-scanning annotations, still
non-blocking)" as the first hardening item after the Phase 0 MVP. Phase 0 is fully implemented:
`core`'s `OutputRenderer` SPI has exactly one production implementation today
(`output/github-pr`'s `GitHubPrCommentRenderer`) plus the always-safe `output/api`'s
`ConsoleOutputRenderer`. Both are wired into `cmd/src/main/java/dev/reachlayer/cli/Main.java`'s
`buildOutputRenderers(...)`.

This spec adds a second, wholly independent `OutputRenderer`: `output/sarif`'s
`SarifOutputRenderer`, which serializes a `RankedReport` as a SARIF 2.1.0 JSON file. SARIF
(Static Analysis Results Interchange Format) is the format GitHub's code-scanning feature
consumes via the `github/codeql-action/upload-sarif` Action step, and is also readable by most
other CI security dashboards. Writing this file is *this* module's entire job — Reachlayer does
not call GitHub's upload API itself (see "Non-goals").

## Goal

1. A new Gradle module `output/sarif` containing `SarifOutputRenderer implements OutputRenderer`
   that renders a `RankedReport` as a syntactically valid SARIF 2.1.0 document to a caller-supplied
   `Path`.
2. `cmd/Main.java` grows one new additive CLI flag, `--sarif-out` (blank ⇒ skip, exactly the
   `--out` pattern), so the renderer is reachable from both the CLI and `action.yml`.
3. Any failure to build or write the SARIF document degrades to a logged warning, never a build
   failure — the same non-negotiable guarantee every other `OutputRenderer` already provides
   (PLAN.md principle 1).
4. `action.yml` gets a new optional `sarif-out` input threaded to `--sarif-out`, and a short new
   doc (`docs/sarif-output.md`) shows the one extra workflow step (`upload-sarif`) a consumer adds
   to get GitHub code-scanning annotations — without Reachlayer itself talking to that API.

## Non-goals (explicitly out of scope for this pass)

- **No GitHub SARIF upload API call.** `github/codeql-action/upload-sarif` is a separate workflow
  step the *consumer's* CI adds; Reachlayer's job stops at "write a valid file to disk." Building
  an uploader would duplicate an Action GitHub already publishes and maintains — pure scope creep.
- **No changes to `core`, `connectors`, `reachability`, `enrich`, `scoring`, `advisor`, or
  `output/api`/`output/github-pr`.** Every field this renderer reads already exists on `Finding`/
  `RankedReport`/`Location`/etc. (verified by direct reading, not guessed — see "Reference" table
  below). This is purely an additive module plus additive wiring in `cmd` and `action.yml`.
- **No SARIF schema validation library dependency.** We hand-build a minimal-but-correct object
  graph covering exactly the properties GitHub's code-scanning ingestion needs (`$schema`,
  `version`, `runs[].tool.driver.{name,rules[]}`, `runs[].results[]`) and serialize it with the
  Jackson `ObjectMapper` already a transitive dependency of every other module (`output/github-pr`
  already depends on `jackson-databind` directly — see its `build.gradle.kts`). Adding a
  third-party SARIF SDK for one output shape is unnecessary weight.
- **No live network calls** — this renderer does pure in-memory mapping + local file I/O, so there
  is nothing to fake in tests beyond a `@TempDir Path`.
- **No `GITHUB_OUTPUT`/`::set-output` wiring for the new `sarif-path` Action output.** The existing
  `report-path` output in `action.yml` has the same property today — it's declared but nothing in
  `cmd` ever writes to `$GITHUB_OUTPUT`. This is a pre-existing gap, not something this feature
  introduces; fixing it for both outputs at once is a reasonable *follow-up*, flagged here for
  visibility, not bundled into this plan.

## SARIF schema mapping (the core design decision)

### Top-level shape

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "Reachlayer", "informationUri": "...", "version": "...", "rules": [...] } },
      "results": [...]
    }
  ]
}
```

One `run` per `RankedReport` (Reachlayer only ever produces one report per invocation today — no
multi-run scenario exists in `Orchestrator`, so a single-run document is the correct, simplest
mapping; nothing here prevents adding more runs later if that changes).

`driver.name`/`informationUri`/`version` are static constants (`"Reachlayer"`,
`"https://github.com/reachlayer/reachlayer"`, `"0.1.0-SNAPSHOT"` — matching the root
`build.gradle.kts` `version` string at time of writing). These are not read from Gradle metadata at
runtime; keeping them in sync when the project version bumps is a known, accepted manual step, not
solved by this pass.

### Rule-id scheme: **`{source}:{discriminator}`**

Decision: one SARIF *rule* per distinct "kind of finding," so that GitHub's code-scanning UI groups
repeated instances of the same underlying issue (e.g. "CWE-89 SQL Injection" flagged in five
different files) under one rule, the way SARIF is designed to work — this is the entire reason
`rules[]` and `results[].ruleId` are separate arrays in the spec.

`discriminator` is chosen by this fallback chain, per finding, in order of specificity:
1. `finding.cwe().get(0)` if `cwe()` is non-empty (e.g. `"CWE-89"`) — a CWE is the most stable,
   scanner-independent "type" identifier available on `Finding`.
2. else `finding.cve().get(0)` if `cve()` is non-empty (e.g. `"CVE-2021-44228"`) — common for SCA
   findings, which frequently have a CVE but no CWE.
3. else a slugified `finding.title()` (lowercase, non-alphanumeric runs collapsed to `-`, truncated)
   — the last-resort fallback for findings with neither, so no finding is ever without a rule.
4. else the literal `"unspecified"` if title is also blank/null.

`source` (e.g. `"fortify"`/`"blackduck"`) is prefixed so two different scanners' rules with an
identical CWE never collide into one rule and hide which scanner actually reported it —
`fortify:CWE-89` and `blackduck:CWE-89` are two distinct rules; distinct provenance is exactly what
a developer needs to trust the row.

The *first* finding encountered for a given `ruleId` (report order — `RankedReport.findings()` is
already risk-sorted) supplies that rule's `name` (set to the ruleId itself, per SARIF convention
that `name` is a stable machine-oriented identifier) and `shortDescription`/`fullDescription` (from
`title()`/`description()`). Subsequent findings sharing that `ruleId` reuse the existing rule entry
— `rules[]` size equals the number of *distinct* rule ids, not the number of findings.

`rules[].properties.tags` = `["security", finding.kind().wireValue()]` (`"sast"`/`"sca"`) and, when
`finding.cvss().isKnown()`, `rules[].properties["security-severity"]` = the CVSS score formatted to
one decimal — this is a GitHub-specific SARIF extension property that drives severity coloring in
GitHub's Security tab, documented by GitHub's code-scanning SARIF support pages.

### `results[]`: one per `Finding`, in `RankedReport.findings()` order

| SARIF field | Source | Notes |
|---|---|---|
| `ruleId` / `ruleIndex` | computed above | `ruleIndex` = index into `driver.rules[]`, recommended by the SARIF spec for faster consumer lookup. |
| `level` | `riskScore()` bucketed, else `severity()` bucketed | See level mapping below. |
| `message.text` | composed | Must include risk score, reachability, and fix suggestion per this feature's explicit requirement — SARIF's `message` is exactly the "annotate the code with why this matters" field. |
| `locations[]` | `location()` when `file()` present, else a synthetic dependency path | See location mapping below. |
| `partialFingerprints["reachlayerFindingId/v1"]` | `finding.id()` | Lets GitHub (and any other SARIF-fingerprint-aware consumer) track the *same* finding stably across runs, independent of line-number drift — reuses the same stable id `Finding.stableId(...)` already guarantees for PR-comment dedup. |
| `properties` | `source`, `severity`, `reachability`, `kev`, `cve`/`cwe` (when non-empty), `riskScore` (when non-null) | Free-form passthrough so any downstream tool that reads raw SARIF properties (not just GitHub) still gets full context, not just the flattened message text. |

**Level mapping** (SARIF only has `none`/`note`/`warning`/`error`): primarily bucket the 0–100
`riskScore` computed by `scoring/RiskScorer` per `PLAN.md` §8's blended formula — `>=75` → `error`,
`>=40` → `warning`, else `note`. When `riskScore()` is `null` (defensive case; the normal pipeline
always scores before rendering, but a renderer must never assume its caller's ordering), fall back
to a coarse `severity()` string match (`"critical"`/`"high"` → `error`, `"medium"`/`"moderate"` →
`warning`, anything else including `"unknown"` → `note`) — the conservative default (least
alarming) when genuinely uncertain, consistent with the project's existing bias of defaulting to
`UNKNOWN` rather than overclaiming (see `Reachability`'s own doc comment).

**Location mapping** — SARIF's `physicalLocation.artifactLocation.uri` is the one field GitHub's
code-scanning UI needs to show an inline annotation. `Location` is *never* `null` on a `Finding`
(constructor defaults to `Location.unknown()`), but its `file()`/`startLine()` fields individually
are frequently `null` — SCA findings normally carry only a `Component`, no file/line at all.

Decision:
- If `location().file()` is non-blank: use it verbatim as the `uri` (same convention
  `MarkdownReportFormatter`/`Location.toString()` already use — treat it as already relative to
  repo root, no rewriting). If `startLine()` is present, add a `region` (`startLine`, `endLine`
  defaulting to `startLine` if `endLine()` is null); if `startLine()` is null, omit `region`
  entirely (SARIF allows a bare `artifactLocation` with no `region`).
- If `file()` is blank/null but `component()` is present (the common SCA case): synthesize
  `uri = "dependencies/" + component().coordinate()` (e.g. `dependencies/org.apache.commons:commons-compress@1.21`).
  This is **not** a real on-disk path — GitHub's UI will list such a result in the Security tab's
  alert list but won't offer an inline file annotation for it, which is the honest outcome for a
  dependency finding with no line-level location. The result's `properties` map gets
  `"reachlayerSyntheticLocation": true` so any consumer (including a future Reachlayer dashboard)
  can tell a synthetic location from a real one without string-sniffing the URI.
- If neither `file()` nor `component()` is available (should not happen for a well-formed
  `Finding`, but defended against): fall back to the literal placeholder `"UNKNOWN_LOCATION"`,
  also flagged synthetic.

This mirrors `MarkdownReportFormatter`'s existing philosophy: never throw on a sparsely populated
`Finding`, always degrade gracefully to a documented placeholder rather than omitting the finding.

### Null handling in the serialized JSON

The shared `ObjectMapper` is configured with `JsonInclude.Include.NON_NULL`, so genuinely absent
optional fields (`region` when there's no line number, `fullDescription` falling back to
`shortDescription`'s text rather than emitting `null`, `security-severity` when CVSS is unknown)
are omitted from the JSON entirely rather than serialized as literal `null` — keeping the document
closer to strict SARIF-schema conformance (several validators reject `null` for fields typed as
plain `string`).

## Module / file layout

New Gradle module `output/sarif` (leaf name `sarif` doesn't collide with any other module, so
unlike `output/api` it needs no `group`/`archivesName` override):

```
output/sarif/
├── build.gradle.kts
├── src/main/java/dev/reachlayer/output/sarif/
│   ├── SarifModel.java            # nested public records: the SARIF object graph, Jackson-serializable as-is
│   ├── SarifReportBuilder.java     # pure: RankedReport -> SarifModel.SarifLog (no I/O), mirrors MarkdownReportFormatter's split
│   └── SarifOutputRenderer.java    # implements OutputRenderer; owns the ObjectMapper + file write, wraps IOException as OutputException
└── src/test/java/dev/reachlayer/output/sarif/
    ├── SarifReportBuilderTest.java
    └── SarifOutputRendererTest.java
```

`output/sarif`'s `build.gradle.kts` depends on `:core` and `jackson-databind` only — deliberately
**not** on `:output:api`, since it doesn't reuse `MarkdownReportFormatter` (different output
format entirely); this keeps the module's dependency footprint identical in shape to
`output/github-pr`'s (which also declares both dependencies directly) minus the `:output:api`
dependency it doesn't need.

## Wiring changes (additive only)

- `settings.gradle.kts`: add `"output:sarif"` to the `include(...)` block.
- `cmd/build.gradle.kts`: add `implementation(project(":output:sarif"))`.
- `cmd/Main.java`: add `@Option(names = "--sarif-out", defaultValue = "", ...) String sarifOut;`
  and extend `buildOutputRenderers(Path outFile, boolean attemptPrComment, Path sarifOutFile)` with
  a third parameter — when non-null, add `new SarifOutputRenderer(sarifOutFile)` to the returned
  list before the (unconditional) `ConsoleOutputRenderer` or the (conditional) PR-comment renderer;
  order doesn't matter since `Orchestrator.renderAll` iterates all renderers independently and
  catches each one's failure separately. `MainWiringIT`'s existing call site
  (`Main.buildOutputRenderers(outFile, false)`) is updated to the new 3-arg signature (passing
  `null` preserves its existing behavior exactly) since it's the only other caller, and it lives in
  the same module this plan is already changing.
- `action.yml`: new optional input `sarif-out` (default `""`), threaded as
  `"--sarif-out=${{ inputs.sarif-out }}"` in the Docker `args:` list (always passed, blank ⇒ skip —
  identical pattern to every other path input already there), plus a new declared output
  `sarif-path` (documented only, matching the pre-existing `report-path` output's current
  not-actually-wired state — see Non-goals).
- `Dockerfile`: **no change needed** — it already does `COPY output ./output`, a whole-directory
  copy that picks up the new `output/sarif` subdirectory automatically.
- New doc `docs/sarif-output.md`: explains what the renderer produces and shows the one-line
  `github/codeql-action/upload-sarif@v3` workflow step a consumer adds to actually get GitHub
  code-scanning annotations from the file Reachlayer writes.
- `docs/architecture.md` and `PLAN.md`'s Phase 1 bullet get a one-line status update (small
  follow-up task at the end of the implementation plan, not the bulk of it, per the task brief).

## Non-blocking guarantee (how this plan proves it)

- `SarifReportBuilder.build(...)` is written defensively like `MarkdownReportFormatter.format(...)`
  — every `Finding` accessor that can be `null`/empty is guarded, and a dedicated test
  (`neverThrowsOnSparselyPopulatedFinding`) builds a `Finding` with only `id`/`source`/`kind` set
  (everything else left at its constructor default) and asserts `build(...)` completes without
  throwing.
- `SarifOutputRenderer.render(...)` catches `IOException` from both directory creation and the
  Jackson write, re-throwing as `OutputException` per the `OutputRenderer` contract; a dedicated
  test forces an `IOException` (by pointing `outputFile` at a path that is already a directory) and
  asserts the resulting `OutputException` wraps it with a message containing the target path.
- Even if some future edit to `SarifReportBuilder` introduced an unguarded `NullPointerException`,
  `Orchestrator.renderAll(...)` already catches `OutputException | RuntimeException` per-renderer
  (see `core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java`) — this is the same
  backstop every other renderer already relies on, not something new introduced here.

## Reference: exact signatures this plan reads (verified by direct reading)

```java
// core/src/main/java/dev/reachlayer/core/spi/OutputRenderer.java
public interface OutputRenderer { String name(); void render(RankedReport report) throws OutputException; }

// core/src/main/java/dev/reachlayer/core/spi/OutputException.java
public class OutputException extends Exception { OutputException(String, Throwable); OutputException(String); }

// core/src/main/java/dev/reachlayer/core/model/RankedReport.java
public record RankedReport(List<Finding> findings, String repo, Instant generatedAt, int topN)

// core/src/main/java/dev/reachlayer/core/model/Finding.java  (all accessors used by this plan)
String id(); String source(); FindingKind kind(); List<String> cve(); List<String> cwe();
Component component(); Location location(); String severity(); Cvss cvss(); String title();
String description(); Reachability reachability(); String reachEvidence(); Epss epss();
boolean kev(); BlastRadius blastRadius(); Double riskScore(); RiskExplanation riskExplanation();
FixSuggestion fixSuggestion();

// core/src/main/java/dev/reachlayer/core/model/Location.java
public record Location(String file, Integer startLine, Integer endLine, String methodSignature)
// never null on a Finding; individual fields may be null. Location.unknown() = all-null.

// core/src/main/java/dev/reachlayer/core/model/Component.java
public record Component(String name, String version, String ecosystem) { public String coordinate(); }

// core/src/main/java/dev/reachlayer/core/model/Cvss.java
public record Cvss(Double score, String vector) { public boolean isKnown(); } // UNKNOWN = (null,null)

// core/src/main/java/dev/reachlayer/core/model/FindingKind.java, Reachability.java
enum FindingKind { SAST, SCA; String wireValue(); }
enum Reachability { REACHABLE, UNREACHABLE, UNKNOWN; String wireValue(); }

// core/src/main/java/dev/reachlayer/core/model/RiskExplanation.java
public record RiskExplanation(Map<String,String> factors) { public String render(); } // "f: v; f2: v2"

// output/github-pr/build.gradle.kts (the sibling module's dependency shape, mirrored minus output:api)
val jacksonVersion: String by rootProject.extra
dependencies {
    implementation(project(":output:api"))
    implementation(project(":core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}

// output/api/.../ConsoleOutputRenderer.java (the Path-writing convention this renderer follows)
public ConsoleOutputRenderer(PrintStream out, Path outputFile) // outputFile nullable = skip

// cmd/src/main/java/dev/reachlayer/cli/Main.java (current signature this plan extends)
static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment)
```
