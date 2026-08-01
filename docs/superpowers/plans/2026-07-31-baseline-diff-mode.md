# Baseline/Diff Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Reachlayer run compare its findings against a baseline (a JSON snapshot of finding ids from a prior run) and tag each finding `isNew: true/false`, so `MarkdownReportFormatter` can foreground *new* findings in the rendered PR comment while still fully listing pre-existing ones (never suppressing data). Wire it additively into `cmd`'s `Main` CLI via two new flags (`--baseline-in`, `--baseline-out`) and into `action.yml` via two matching inputs; document the two-job CI pattern a consumer wires up. See `docs/superpowers/specs/2026-07-31-baseline-diff-mode-design.md` for full rationale — this plan implements that spec task-by-task.

**Architecture:** A new `core.baseline` package (no new Gradle module — `core` already has every dependency this needs) containing `Baseline` (domain record), `BaselineStore` (static JSON file read/write, never throws), and `BaselineDiffer` (pure static tagging logic). `Finding` grows a fifth progressive-enrichment field, `isNew` (nullable `Boolean`), via the exact existing builder pattern. A new `core.pipeline.BaselineStage` functional interface mirrors the other four stages and is wired into `Orchestrator` via a **new, additive 8-arg constructor overload** — the existing 7-arg constructor and all its current call sites are untouched. `MarkdownReportFormatter` gains a baseline-aware rendering branch that only activates when at least one finding has non-null `isNew()`; the undiffed branch is byte-for-byte identical to today. `cmd/Main.java` grows two CLI options and two new package-private static methods.

**Tech Stack:** Java 21, Jackson `jackson-databind` (already an `api` dependency of `core` — no new module dependency needed anywhere), JUnit 5 + AssertJ (repo-wide standard), picocli (already a `cmd` dependency).

## Global Constraints

- No changes to `connectors`, `reachability`, `enrich`, `scoring`, `advisor`, `output/github-pr`, or `output/sarif` — `Finding.stableId(...)` already provides everything this feature needs.
- No new Gradle module, no `settings.gradle.kts` change, no `build.gradle.kts` change anywhere.
- Every existing test file's existing test methods/assertions are left completely unmodified — this plan only *adds* new test methods, and only *adds* new files elsewhere.
- Never fail the build: `BaselineStore.read(...)` returns `null` (never throws) on any missing/malformed input; `BaselineStore.write(...)` never throws; `BaselineDiffer.tag(...)` is a total pure function; `Orchestrator.run(...)`'s existing `safeStage(...)` wraps the baseline stage exactly like every other stage.
- `--baseline-in` / `--baseline-out` follow the exact same "blank string ⇒ not provided, never an error" convention as `--sarif-out`/`--out`/`--fortify`/etc.
- Follow existing test conventions exactly: `@TempDir Path tempDir` for anything touching disk, JUnit 5 `@Test`, AssertJ `assertThat`/`assertThatCode`, no mocking framework.
- Use `./gradlew` (Linux wrapper) for all commands in this execution environment.

---

## Reference: exact signatures this plan wires together

```java
// core/src/main/java/dev/reachlayer/core/model/Finding.java — current full field/accessor list;
// this plan adds one new field (isNew) following this exact pattern
private final FixSuggestion fixSuggestion;
private Finding(Builder b) { ... this.fixSuggestion = b.fixSuggestion; }
public FixSuggestion fixSuggestion() { return fixSuggestion; }
public Builder toBuilder() { ... b.fixSuggestion = fixSuggestion; return b; }
public static final class Builder {
    private FixSuggestion fixSuggestion;
    public Builder fixSuggestion(FixSuggestion fixSuggestion) { this.fixSuggestion = fixSuggestion; return this; }
    public Finding build() { return new Finding(this); }
}

// core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java — current 7-arg constructor
// (kept unmodified) and run() method this plan extends
public Orchestrator(List<ScannerConnector>, ReachabilityStage, EnrichmentStage, ScoringStage,
        AdvisorStage, List<OutputRenderer>, ReachlayerConfig)
public RankedReport run(List<ScanSource> sources, String repoLabel)
private List<Finding> safeStage(String name, Supplier<List<Finding>> stage, List<Finding> fallback)

// core/src/main/java/dev/reachlayer/core/pipeline/ReachabilityStage.java (the pattern BaselineStage mirrors)
@FunctionalInterface
public interface ReachabilityStage { List<Finding> tag(List<Finding> findings); }

// output/api/src/main/java/dev/reachlayer/output/api/MarkdownReportFormatter.java — current full
// format(...) body (Task 3 extracts this verbatim into appendUndiffedBody(...))

// cmd/src/main/java/dev/reachlayer/cli/Main.java — current fields/methods this plan extends
@Option(names = "--sarif-out", defaultValue = "", description = "...") private String sarifOut;
private void runPipeline() throws IOException
static ReachabilityStage buildReachabilityStage(String classesDir)
```

---

### Task 1: `core.baseline` package — `Baseline`, `BaselineStore`, `BaselineDiffer`, plus `Finding.isNew`

**Files:**
- Create: `core/src/main/java/dev/reachlayer/core/baseline/Baseline.java`
- Create: `core/src/main/java/dev/reachlayer/core/baseline/BaselineStore.java`
- Create: `core/src/main/java/dev/reachlayer/core/baseline/BaselineDiffer.java`
- Modify: `core/src/main/java/dev/reachlayer/core/model/Finding.java` (add `isNew` field)
- Test: `core/src/test/java/dev/reachlayer/core/baseline/BaselineStoreTest.java`
- Test: `core/src/test/java/dev/reachlayer/core/baseline/BaselineDifferTest.java`

No `settings.gradle.kts` / `build.gradle.kts` change — `core` already depends on `jackson-databind` (`api`) and gets `slf4j-api`/JUnit/AssertJ from the root project.

- [ ] **Step 1: Add `Finding.isNew`, then write the failing tests**

Add the `isNew` field to `Finding` first (needed for `BaselineDifferTest` to compile): field
`private final Boolean isNew;` after `fixSuggestion`; constructor `this.isNew = b.isNew;`;
accessor `public Boolean isNew()`; `toBuilder()` copies `b.isNew = isNew;`; `Builder` gets
`private Boolean isNew;` + `public Builder isNew(Boolean isNew) { this.isNew = isNew; return this; }`.

Create `BaselineStoreTest.java` and `BaselineDifferTest.java` covering: write-then-read round trip;
missing parent directories created on write; `read` returns `null` for missing file, `null` path,
and malformed JSON (never throws); `write` is a no-op and never throws for a `null` path; written
JSON contains `generatedAt`/`findingIds`; `BaselineDiffer.tag` marks absent-from-baseline as `true`
and present as `false`; `null` baselineIds is identity (same reference, `isNew()` untouched); empty
baseline tags everything `true`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :core:compileTestJava`
Expected: FAIL — `Baseline`/`BaselineStore`/`BaselineDiffer` and `Finding.isNew()` don't exist yet.

- [ ] **Step 3: Write minimal implementation**

`Baseline` is a record `(Instant generatedAt, Set<String> findingIds)` with a compact constructor
defaulting `findingIds` to `Set.of()`/`Set.copyOf(...)`.

`BaselineStore`: static `read(Path)` returns `null` on `null`/missing/malformed input (catch
`IOException | RuntimeException`, log a warning); static `write(Path, Set<String>, Instant)`
creates parent dirs, writes pretty-printed JSON via a plain `ObjectMapper` (no jsr310 module — the
on-disk DTO stores `generatedAt` as `Instant.toString()`, mirroring `EpssClient`/`KevClient`'s own
cache-file DTOs' plain-`String` date fields), catches `IOException` and logs a warning, never
throws. Internal `private record BaselineFile(String generatedAt, List<String> findingIds)` is the
on-disk shape.

`BaselineDiffer`: static `tag(List<Finding>, Set<String>)` — `null` baselineIds returns `findings`
unchanged (identity); otherwise maps each finding to `f.toBuilder().isNew(!baselineIds.contains(f.id())).build()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :core:test --tests "dev.reachlayer.core.baseline.*"`
Expected: PASS, all new tests.

- [ ] **Step 5: Run the full `core` test suite to confirm no regression from the `Finding` change**

Run: `./gradlew :core:test`
Expected: BUILD SUCCESSFUL — every existing test still passes (the new `isNew` field defaults to
`null`, which every existing assertion already implicitly expects since none of them touch it).

- [ ] **Step 6: Commit**

```bash
git add core/src/main/java/dev/reachlayer/core/model/Finding.java core/src/main/java/dev/reachlayer/core/baseline/
git commit -m "feat(core): add Finding.isNew and core.baseline package (Baseline/BaselineStore/BaselineDiffer)"
```

---

### Task 2: `BaselineStage` + `Orchestrator` wiring (additive 8-arg constructor overload)

**Files:**
- Create: `core/src/main/java/dev/reachlayer/core/pipeline/BaselineStage.java`
- Modify: `core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java`
- Modify: `core/src/test/java/dev/reachlayer/core/model/FindingTest.java` (add one test)
- Modify: `core/src/test/java/dev/reachlayer/core/pipeline/OrchestratorTest.java` (add two tests)

**IMPORTANT — verify before writing:** read the CURRENT `FindingTest.java` and `OrchestratorTest.java`
on disk first to confirm exact existing helper/fake shapes (e.g. how a fake `ScannerConnector` is
built in existing tests) before adding new methods, since this plan's author could not directly
verify every line of those two test files against the very latest disk state.

- [ ] **Step 1: Write the failing tests**

Add to `FindingTest`: a test that `isNew()` defaults to `null`, and that `toBuilder().isNew(true).build()`
sets it without mutating the original.

Add to `OrchestratorTest`: (a) a test constructing `Orchestrator` via the new 8-arg constructor with
a `BaselineStage` that tags everything `isNew(true)`, asserting the returned report's findings all
have `isNew() == true`; (b) a test confirming the existing 7-arg constructor still leaves every
finding's `isNew()` as `null`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :core:compileTestJava`
Expected: FAIL — `BaselineStage` doesn't exist yet, no 8-arg `Orchestrator` constructor exists yet.

- [ ] **Step 3: Write minimal implementation**

Create `BaselineStage` — `@FunctionalInterface` with `List<Finding> tag(List<Finding> findings)`,
mirroring `ReachabilityStage`.

Modify `Orchestrator`: add `private final BaselineStage baselineStage;` field. Keep the existing
7-arg constructor but make it delegate: `this(connectors, reachabilityStage, enrichmentStage,
scoringStage, advisorStage, null, outputRenderers, config);`. Add a new 8-arg constructor
inserting `BaselineStage baselineStage` between `advisorStage` and `outputRenderers`, defaulting a
`null` baselineStage to the identity stage (`findings -> findings`). In `run(...)`, insert a
`safeStage("baseline", () -> baselineStage.tag(afterAdvisor), findings)` call right after the
advisor stage and before `RankedReport.of(...)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :core:test`
Expected: BUILD SUCCESSFUL — every existing test (including `OrchestratorTest`'s pre-existing 7-arg-constructor tests) still passes unmodified, plus all new tests from Tasks 1-2.

- [ ] **Step 5: Commit**

```bash
git add core/src/main/java/dev/reachlayer/core/pipeline/BaselineStage.java core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java core/src/test/java/dev/reachlayer/core/model/FindingTest.java core/src/test/java/dev/reachlayer/core/pipeline/OrchestratorTest.java
git commit -m "feat(core): add BaselineStage and wire it into Orchestrator via an additive 8-arg constructor"
```

---

### Task 3: `MarkdownReportFormatter` baseline-aware rendering

**Files:**
- Modify: `output/api/src/main/java/dev/reachlayer/output/api/MarkdownReportFormatter.java`
- Modify: `output/api/src/test/java/dev/reachlayer/output/api/MarkdownReportFormatterTest.java` (add tests only)

- [ ] **Step 1: Write the failing tests**

Add tests asserting: (1) with no finding having `isNew()` set, output contains no baseline
headings (unchanged from today); (2) with a mix of new/existing findings, output contains the
"N new, M pre-existing" summary line, a "### New findings introduced by this change" heading
followed by new findings, and a "### Pre-existing findings (unchanged from baseline)" heading
followed by existing findings, with new findings NOT appearing in the existing section and vice
versa; (3) when there are zero new findings, a reassuring "_No new findings..._" message appears
instead of an empty table, and existing findings are still listed; (4) when there are zero
pre-existing findings, no "Pre-existing findings" section appears at all; (5) new findings beyond
`topN` are collapsed into their own "Show all N new findings" block, separate from the
pre-existing section.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :output:api:test --tests "dev.reachlayer.output.api.MarkdownReportFormatterTest"`
Expected: FAIL — new assertions don't match today's output; every pre-existing test still passes.

- [ ] **Step 3: Write minimal implementation**

Split `format(...)` into a thin dispatcher: compute `boolean baselineActive = report.findings().stream().anyMatch(f -> f.isNew() != null);`
after emitting the marker/heading lines, then call either `appendUndiffedBody(sb, report)` (an
exact, verbatim copy of today's entire body — same variable names, same table calls, so there is
zero behavioral drift) or `appendBaselineAwareBody(sb, report)`.

`appendBaselineAwareBody`: partition `report.findings()` into `newFindings` (`isNew() == true`) and
`existingFindings` (everything else, i.e. `false` or — defensively — anything not `true`). Emit the
summary line, then the "New findings" heading with either the reassuring empty-state message or a
risk-ranked table capped at `report.topN()` with overflow in its own `<details>` block (reusing
`appendTable(...)` unchanged). Then, only if `existingFindings` is non-empty, emit the
"Pre-existing findings" heading with a single `<details>` block listing every existing finding
(no further pagination).

`appendTable(...)` and every other private helper are unchanged and reused as-is.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :output:api:test`
Expected: BUILD SUCCESSFUL — every pre-existing test passes unmodified, plus all new tests.

- [ ] **Step 5: Commit**

```bash
git add output/api/src/main/java/dev/reachlayer/output/api/MarkdownReportFormatter.java output/api/src/test/java/dev/reachlayer/output/api/MarkdownReportFormatterTest.java
git commit -m "feat(output-api): render new-vs-pre-existing findings separately in baseline/diff mode"
```

---

### Task 4: Wire `--baseline-in`/`--baseline-out` into `cmd/Main.java`

**Files:**
- Modify: `cmd/src/main/java/dev/reachlayer/cli/Main.java`
- Modify: `cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java` (add tests only)

No `cmd/build.gradle.kts` change needed.

- [ ] **Step 1: Write the failing tests**

Add tests asserting: `buildBaselineStage("")` is identity; `buildBaselineStage(<missing file path>)`
degrades to identity (isNew stays null); `buildBaselineStage(<real baseline file>)` correctly tags
new vs. old findings; `writeBaselineIfRequested` is a no-op when the path is blank; when a path is
given, it writes every finding's id to a baseline file readable back via `BaselineStore.read`. Add
one end-to-end test running the real fixtures twice (mirroring the existing
`runsFullPipelineAgainstRealFixturesAndProducesAScoredRenderedReport`'s wiring shape) — first run
writes `--baseline-out`, second run (same fixtures, so an identical finding-id corpus) reads it via
`--baseline-in` and asserts every finding comes back `isNew() == false`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :cmd:compileTestJava`
Expected: FAIL — `Main.buildBaselineStage`/`Main.writeBaselineIfRequested` don't exist yet.

- [ ] **Step 3: Update `Main.java`**

Add imports for `core.baseline.{Baseline,BaselineDiffer,BaselineStore}` and
`core.pipeline.BaselineStage`, plus `core.model.{Finding,RankedReport}` if not already imported.
Add two new `@Option` fields (`--baseline-in`, `--baseline-out`) after `--sarif-out`, same
blank-means-skip convention. In `runPipeline()`, build `BaselineStage baselineStage =
buildBaselineStage(baselineIn);`, pass it into the `Orchestrator`'s new 8-arg constructor, capture
the returned `RankedReport`, and call `writeBaselineIfRequested(report, baselineOut);` after
`orchestrator.run(...)` returns. Add the two new package-private static methods exactly as
specified in the design spec's Decision 4 (identical implementation).

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :cmd:test --tests "dev.reachlayer.cli.MainWiringIT"`
Expected: PASS — every pre-existing test unmodified, plus all new tests.

- [ ] **Step 5: Run the full `cmd` test suite**

Run: `./gradlew :cmd:test`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Commit**

```bash
git add cmd/src/main/java/dev/reachlayer/cli/Main.java cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java
git commit -m "feat(cmd): wire --baseline-in/--baseline-out into Main and Orchestrator"
```

---

### Task 5: `action.yml`, `docs/baseline-mode.md`, `docs/architecture.md`, `PLAN.md`

**Files:**
- Modify: `action.yml`
- Create: `docs/baseline-mode.md`
- Modify: `docs/architecture.md`
- Modify: `PLAN.md`

Add `baseline-in`/`baseline-out` inputs and a `baseline-out-path` output to `action.yml`, threaded
into the Docker `args:` list exactly like `sarif-out` was in the prior pass (verify the CURRENT
`action.yml` on disk first — it already has `sarif-out` wired in from that pass). Write
`docs/baseline-mode.md` documenting the JSON shape, the "Reachlayer only diffs/writes, doesn't
orchestrate which branch is baseline" boundary, and an example two-job GitHub Actions workflow
(base-branch job writes+uploads an artifact; PR job downloads+diffs, tolerating a missing artifact
on a repo's very first run). Update `docs/architecture.md`'s `core` module row and data-flow
diagram to mention baseline tagging. Update `PLAN.md`'s Phase 1 baseline/diff bullet to note it's
implemented, pointing at `docs/baseline-mode.md`.

- [ ] **Step 1-4:** apply the four doc edits above.

- [ ] **Step 5: Commit**

```bash
git add action.yml docs/baseline-mode.md docs/architecture.md PLAN.md
git commit -m "docs: document baseline/diff mode and action.yml baseline-in/baseline-out inputs"
```

---

### Task 6: Full build verification and one manual end-to-end run

- [ ] **Step 1:** `./gradlew build` — BUILD SUCCESSFUL, every module's tests pass.

- [ ] **Step 2:** Run the CLI twice against the real fixtures — first with `--baseline-out
  reachlayer-baseline.json`, then (same fixtures) with `--baseline-in reachlayer-baseline.json` —
  confirm the second run's report says "no new findings" and lists all 5 as pre-existing, and the
  baseline JSON file contains 5 ids.

- [ ] **Step 3:** Clean up the manual run's output files (do not commit them).

- [ ] **Step 4:** `./gradlew build` again to confirm a clean final state.

---

## Self-review notes

- **Zero modifications to any existing test method** — every touched test file only gains new
  methods; `Orchestrator`'s additive constructor overload (not signature extension) is what makes
  this possible, unlike the SARIF pass which had to update one existing call site.
- **Backward-compat rendering is structurally enforced**: `appendUndiffedBody(...)` is a verbatim
  copy of today's `format(...)` body, sharing no code path with the new baseline-aware branch that
  could leak new behavior into the undiffed case.
- **Never-fail guarantee traced end to end**: `BaselineStore` never throws → `Main.buildBaselineStage`
  never throws → `Orchestrator`'s `safeStage("baseline", ...)` is an additional backstop.
- **Pre-existing gap flagged, not silently fixed**: `action.yml`'s `report-path`/`sarif-path`
  outputs were already declared-but-unwired; `baseline-out-path` is added in the same state,
  consistent with how the SARIF pass handled `sarif-path`.
