# Baseline/diff mode — design spec

**Date:** 2026-07-31
**Status:** proposed, proceeding to implementation plan

## Context

`PLAN.md` §5 Phase 1 lists "Baseline/diff mode: only surface *new* findings introduced by the PR
vs. the base branch, to fight backlog noise" as the second Phase 1 hardening item. Phase 0 (MVP)
and Phase 1's first item (`output/sarif`'s `SarifOutputRenderer`, wired via `--sarif-out` /
`action.yml`'s `sarif-out`) are both already implemented and merged.

This spec adds baseline/diff mode: a way for a Reachlayer run to compare its findings against a
**baseline** — a snapshot of finding ids from a prior run, typically a scheduled scan of the base
branch — and tag each current finding as *new* (introduced since the baseline) or *pre-existing*
(already present in it), so the rendered PR comment can foreground the handful of findings a PR
actually introduced, instead of re-surfacing the same 15,000-finding backlog on every PR (the
exact "backlog noise" problem `PLAN.md` §1's vision paragraph names as the core pain point this
project exists to solve).

This is possible with no new correlation logic because **finding ids are already cross-run
stable**: both connectors compute `Finding.stableId(source, rule/cve, location, component)`
(`connectors/fortify/.../FortifyConnector.java:94`, `connectors/blackduck/.../BlackDuckConnector.java:89`),
which hashes source + rule + location file/line + component coordinate — deterministic across two
independent runs of the same underlying finding, with no dependency on scanner-assigned instance
IDs. Baseline/diff mode is pure set-membership on top of an id scheme that already exists.

## Goals

1. A baseline is a small JSON file containing the set of finding ids from a prior run (plus a
   timestamp). A new `core.baseline` package gains `Baseline` (the in-memory domain object),
   `BaselineStore` (read/write the JSON file), and `BaselineDiffer` (pure tagging logic).
2. `Finding` grows a fifth progressively-enriched field, `isNew` (nullable `Boolean`), following
   the exact existing field-addition pattern (constructor default, builder field/method,
   `toBuilder()` copy, accessor).
3. A new `core.pipeline.BaselineStage` functional interface (mirroring `ReachabilityStage` /
   `EnrichmentStage` / `ScoringStage` / `AdvisorStage`) performs the tagging, wired into
   `Orchestrator` via a new, purely additive 8-arg constructor overload — the existing 7-arg
   constructor (and every one of its current call sites) is untouched.
4. `MarkdownReportFormatter` changes its framing — never its data — when baseline mode was active:
   new findings surface in the primary visible table; pre-existing findings are still fully listed,
   just collapsed. When no finding has a non-null `isNew()` (today's default), output is
   byte-for-byte identical to the current renderer.
5. `cmd/Main.java` grows two new additive CLI flags, `--baseline-in` / `--baseline-out`, mirroring
   the exact `--sarif-out` "blank ⇒ skip" precedent.
6. `action.yml` gets two new optional inputs threaded the same way `sarif-out` was in the
   immediately preceding pass, plus a new doc (`docs/baseline-mode.md`) showing the two-job CI
   workflow shape a consumer wires up (base-branch scan writes a baseline artifact; PR run
   downloads and diffs against it) — documentation only, not code.

## Non-goals (explicitly out of scope for this pass)

- **No "detect the base branch and re-run" orchestration.** Deciding which branch is "the
  baseline," triggering a second scan, and passing an artifact between two CI jobs is entirely the
  consumer's CI/workflow-authoring concern. Reachlayer's job is exactly two primitives: *given a
  baseline file, diff against it* and *given a request to write one, write it*. `docs/baseline-mode.md`
  shows an example two-job GitHub Actions shape for illustration only — it is documentation, not a
  feature this plan builds.
- **No changes to `connectors`, `reachability`, `enrich`, `scoring`, `advisor`, `output/github-pr`,
  or `output/sarif`.** `Finding.stableId(...)` already provides everything baseline/diff mode
  needs; no connector changes are required. `output/sarif`'s SARIF mapping is untouched by this
  pass — a future follow-up could surface `isNew` as a SARIF result property, but that's optional
  polish, not required for this feature to work, and is left for later.
- **No new Gradle module.** Unlike `output/sarif` (a genuinely new pluggable `OutputRenderer`
  implementation, appropriately isolated in its own module so `core` doesn't have to depend on
  Jackson-for-SARIF-specifically), baseline/diff mode's I/O is a ~90-line pure-JSON-file
  read/write with no HTTP boundary and no third-party SDK. `core` already declares
  `jackson-databind` as an `api` dependency (`core/build.gradle.kts`) — every module that already
  depends on `core` (`cmd` included) gets it transitively for free. Creating a separate
  `core:baseline` (or top-level `baseline`) module would add Gradle wiring (a new
  `settings.gradle.kts` entry, a new `build.gradle.kts`, a new `cmd/build.gradle.kts` dependency
  line) for a feature two orders of magnitude smaller than `output/sarif`, with no independent
  reuse story (nothing outside `core`/`cmd` needs it). `core.baseline` — a new package inside the
  existing `core` module, alongside the existing `core.config`/`core.model`/`core.pipeline`/`core.spi`
  cross-cutting packages — is the appropriately-sized home.
- **No config-file (`reachlayer.yml`) fields for baseline paths.** `--sarif-out` set the precedent
  of being a pure CLI/Action flag with no `reachlayer.yml` equivalent; baseline paths are
  run-specific (a fresh temp path per CI job, typically), not durable project configuration, so
  they follow the same precedent.
- **No `isNew` field on the SARIF/output model beyond `Finding` itself** — see above.
- **No live network calls** — this feature is pure in-memory tagging + local file I/O, identical in
  spirit to `EpssClient`/`KevClient`'s cache-file read/write, so nothing needs faking in tests
  beyond a `@TempDir Path`.

## Design decision 1: what a baseline is, concretely

A baseline is the JSON file:

```json
{
  "generatedAt": "2026-07-31T12:00:00Z",
  "findingIds": ["fortify-1a2b3c", "blackduck-4d5e6f"]
}
```

`generatedAt` is stored as a plain ISO-8601 string (`Instant.toString()`/`Instant.parse(...)`), not
via Jackson's `jackson-datatype-jsr310` module (declared in `core/build.gradle.kts` but not
actually registered/used by any class in the repo today, per direct `grep` — nothing currently
relies on it). This deliberately mirrors `EpssClient`'s and `KevClient`'s own cache-file DTOs
(`enrich/epss/.../EpssClient.java`'s `CacheFile(String asOf, ...)`, `enrich/kev/.../KevClient.java`'s
`CacheFile(String asOf, List<String> cveIds)`), which both store their "last refreshed" timestamp
as a plain `String`, not a typed date — using a plain `ObjectMapper` with no extra module
registration avoids a first-of-its-kind `JavaTimeModule` registration footgun (an unregistered
`Instant` field throws `InvalidDefinitionException` at serialize time) for a field whose only
consumer is a human reading a JSON file or another Reachlayer run parsing an ISO-8601 string it
wrote itself.

`findingIds` is a `List<String>` in the on-disk DTO (again mirroring `KevClient`'s
`CacheFile.cveIds()`, itself a `List<String>`, converted to/from a `Set<String>` at the call site)
— the in-memory domain object (`Baseline`) exposes `Set<String> findingIds()` since membership
testing, not order, is all `BaselineDiffer` needs.

**Round-trip:**

- **Writer** (`--baseline-out`, typically the scheduled base-branch scan job): after a normal
  Reachlayer run completes, the *current* run's finding ids are written to the given path.
- **Reader** (`--baseline-in`, typically the PR run): a prior baseline file is read at the start of
  a run and used to tag every finding's `isNew()` before rendering.

Two independent CLI flags rather than one "baseline mode" toggle, because a single run only ever
needs to do at most one of these (a scheduled base-branch scan writes; a PR run reads) — see
`docs/baseline-mode.md`'s two-job example. Nothing prevents a single invocation from doing both
(reading an old baseline *and* writing a fresh one), which is why they're independent flags, not a
single enum-like option.

**Read/write location:** `core.baseline.BaselineStore`, two static methods:

```java
public static Baseline read(Path path);                                    // null on any failure
public static void write(Path path, Set<String> findingIds, Instant generatedAt);  // never throws
```

Static, not instance-based with an injected fetcher, because there is no I/O boundary to fake here
the way `EpssClient`/`KevClient` fake an HTTP endpoint — tests exercise `BaselineStore` directly
against a real `@TempDir Path`, exactly the way those two clients' own cache-file read/write
methods are exercised in their existing tests (no fake/mock needed for local file I/O, per the
repo's own test-convention notes).

**Never-fail contract:** `read(...)` returns `null` — not an exception, not an `Optional` the
caller might forget to handle — on a `null`/missing/malformed path, exactly modeling "no baseline
available." `write(...)` is a void method that only ever logs a warning on failure; the baseline
file is a side artifact of a run, not something the run's own success depends on, consistent with
`PLAN.md` principle 1 ("never fail or block the build").

## Design decision 2: how new-vs-pre-existing attaches to a `Finding`

A new nullable field, `Boolean isNew`, added via the *exact* existing enrichment-field pattern
already used for `riskScore`, `fixSuggestion`, etc. (verified directly in
`core/src/main/java/dev/reachlayer/core/model/Finding.java`):

- Field: `private final Boolean isNew;`
- Constructor: `this.isNew = b.isNew;` (no special-casing — `Boolean` is already nullable, unlike
  `reachability`/`severity`/etc. which default to a non-null sentinel; `isNew` staying `null` *is*
  the correct default, meaning "no baseline was used for this run").
- Builder: `private Boolean isNew;` field + `public Builder isNew(Boolean isNew)`.
- `toBuilder()`: `b.isNew = isNew;`
- Accessor: `public Boolean isNew()`.

Semantics: `null` = no baseline was used (today's behavior, and the default for every finding
before this feature existed); `true` = the finding's `id()` was absent from the baseline (i.e.
introduced since); `false` = present in the baseline (pre-existing).

**Tagging logic** lives in `core.baseline.BaselineDiffer` — a pure, static, one-method utility, no
I/O, no state:

```java
public static List<Finding> tag(List<Finding> findings, Set<String> baselineIds) {
    if (baselineIds == null) {
        return findings; // no baseline in play -> identity, isNew() stays whatever it already was
    }
    return findings.stream()
            .map(f -> f.toBuilder().isNew(!baselineIds.contains(f.id())).build())
            .toList();
}
```

**Pipeline wiring — the constructor-breakage question.** A new `core.pipeline.BaselineStage`
functional interface is added, shaped exactly like the other four:

```java
@FunctionalInterface
public interface BaselineStage {
    List<Finding> tag(List<Finding> findings);
}
```

Decision: **do not** make this a required 8th parameter on `Orchestrator`'s existing constructor.
Instead, the existing 7-arg constructor is kept completely unchanged and a **new, additive 8-arg
overload** is added that inserts `BaselineStage baselineStage` between `advisorStage` and
`outputRenderers` (mirroring pipeline execution order: reachability → enrichment → scoring →
advisor → baseline → render). The 7-arg constructor delegates to the 8-arg one with
`baselineStage = null`; the 8-arg constructor treats a `null` `baselineStage` as the identity
stage (`findings -> findings`).

Rationale, weighing the two options the task brief poses:

- *Consistency with existing required-stage wiring* would mean every `Orchestrator` construction
  site must now decide what to pass for baseline tagging, even runs that will never use it (the
  overwhelming majority, at least initially — baseline mode requires a consumer to have already
  wired up a two-job CI pattern, see `docs/baseline-mode.md`). It would force a mechanical edit to
  every existing call site: `OrchestratorTest`'s three constructions and `MainWiringIT`'s one,
  none of which have anything to do with baseline/diff mode and would gain a parameter purely to
  keep compiling.
- *Minimizing blast radius of an additive feature* wins here because Java constructor overloading
  makes "purely additive" literally true, not just a design intention — `OrchestratorTest` and
  `MainWiringIT`'s existing 7-arg call sites require **zero code changes** and keep testing exactly
  what they tested before (confirmed by direct reading of both files: all four existing call sites
  use the 7-arg form). Only `cmd/Main.java`'s production wiring — which is the actual point of
  contact for this feature — needs to change, and it changes to the new 8-arg form because it now
  always builds *some* `BaselineStage` (the identity one when `--baseline-in` is blank).

This is the same reasoning `output/sarif`'s prior pass already used for `Main.buildOutputRenderers`
(extended with a 3rd parameter, with `MainWiringIT`'s one call site updated) — the difference here
is that `Orchestrator`'s constructor has *multiple* existing call sites outside `cmd`
(`OrchestratorTest`'s three), which is exactly the scenario where an overload — rather than
extending the existing signature — avoids collateral edits.

**Non-fail guarantee:** the baseline stage is wrapped in `Orchestrator.run(...)`'s existing
`safeStage(...)` helper, identically to every other stage:

```java
List<Finding> afterBaseline = findings;
findings = safeStage("baseline", () -> baselineStage.tag(afterBaseline), findings);
```

Belt-and-suspenders: even though `BaselineDiffer.tag(...)` cannot itself throw for any input
(it only ever calls `Set.contains(...)` and `Finding.toBuilder()`), and even though
`BaselineStore.read(...)` already degrades a corrupt/missing file to `null` (never throwing before
tagging even starts), `safeStage` still wraps the call — consistent with every other stage's
"defense in depth," not because this stage is expected to fail.

**Where it runs:** last, immediately before `RankedReport.of(...)` — after `advisorStage`, not
interleaved with reachability/enrichment/scoring. Baseline tagging is a pure display/grouping
concern (PLAN.md's own Phase 1 bullet list groups it with "suppression-of-*display*-rules, never
suppression of data") with zero interaction with risk scoring, reachability, or fix suggestions —
it only needs `Finding.id()`, which is set at ingestion and never changes. Running it last keeps
its only dependency (the final finding list) obviously satisfied and keeps the change's diff to
`Orchestrator.run(...)` a single three-line insertion.

## Design decision 3: rendering changes in `MarkdownReportFormatter`

**Detection:** baseline mode is "active" for a given report iff at least one finding has
`isNew() != null`:

```java
boolean baselineActive = report.findings().stream().anyMatch(f -> f.isNew() != null);
```

**Hard backward-compatibility requirement:** when `baselineActive` is `false` (the default —
no `--baseline-in` was supplied, so `BaselineStage` never ran, or ran as the identity no-op), the
renderer takes the *exact same code path* it does today, verbatim — every existing
`MarkdownReportFormatterTest` keeps passing completely unmodified. This is achieved by extracting
today's entire `format(...)` body into a private `appendUndiffedBody(...)` method with no
behavioral change whatsoever, and adding a new sibling `appendBaselineAwareBody(...)` that only
runs on the `baselineActive` branch.

**Layout when `baselineActive` is `true`** — combining the two independent axes (new-vs-existing,
and risk-based top-N-vs-rest) without producing a confusing document:

```
## Reachlayer risk triage — {repo}

{N} finding(s) analyzed against the baseline — {M} new, {N-M} pre-existing.

### New findings introduced by this change

[if M == 0]
_No new findings introduced by this change compared to the baseline._

[else]
| Rank | Risk | ... |   <- risk-ranked, capped at report.topN(), exactly like today's top()/rest()
...
[if M > topN]
<details><summary>Show all {M} new findings</summary>
| Rank | Risk | ... |   <- the remaining new findings, still risk-ranked
</details>

[if N-M > 0]
### Pre-existing findings (unchanged from baseline)

<details>
<summary>Show {N-M} pre-existing finding(s)</summary>
| Rank | Risk | ... |   <- ALL pre-existing findings, risk-ranked, never paginated further
</details>
```

Decision rationale for how the two axes combine:

- **New-vs-existing is the primary partition** (which section a finding lands in), because that's
  the entire point of the feature — "what did this PR actually introduce" is the headline question,
  and "the rest of the 15,000-finding backlog" is precisely the noise this feature exists to let a
  developer *not* re-read on every PR.
- **Risk-based top-N pagination only applies within the "new" section.** New findings are exactly
  the ones a developer needs to act on *right now*, and there can still be more of them than fit in
  one glanceable table (a PR can introduce dozens of findings), so the existing `topN`/"show all N"
  collapsible convention is reused unchanged, just scoped to the `newFindings` sublist instead of
  the full report.
- **Pre-existing findings are not further top-N-paginated.** They are, by construction, already the
  deprioritized bucket (that's what "pre-existing, already triaged or already known" means in this
  feature's whole premise) — nesting a second top-N pagination *inside* an already-collapsed
  "pre-existing" section would be pagination-inside-pagination for a bucket nobody is being asked to
  read start-to-finish anyway. One `<details>` block listing everything satisfies PLAN.md principle
  3 ("never suppress a finding") without adding a second axis of complexity the reader has to
  parse. If a future pass wants risk-ordering *cues* within that bucket, the findings are already
  emitted risk-sorted (the list is a filter over `report.findings()`, which `RankedReport.of(...)`
  already sorted descending by `riskScore()`) — only an additional pagination boundary is
  intentionally omitted, not the ordering itself.
- **The `0`-new case gets an explicit reassuring message**, not an empty table — `M == 0` ("this PR
  introduced nothing new") is the single most valuable message this feature can deliver, and an
  empty Markdown table under a heading reads as broken output, not "good news." A literal sentence
  makes the best case maximally legible.
- **No existing-findings section at all when `N - M == 0`** (every finding in the report is new,
  none pre-existing) — an empty collapsible "Show 0 pre-existing findings" block is pure noise with
  nothing being hidden, so it's omitted entirely; this loses no data (there is none in that bucket)
  and keeps PLAN.md principle 3 fully satisfied.
- **Ranks restart at 1 within each independent section** (new-table, new-table's overflow
  `<details>` continues numbering from the new-table per the existing `top()`/`rest()` convention,
  and the pre-existing section restarts its own numbering at 1) rather than one continuous rank
  spanning unrelated groups — new and pre-existing are different semantic partitions, not one
  paginated list, so a shared rank counter across them would misleadingly imply they're one ranked
  sequence when they're two independent groupings.

No change to `RankedReport` is needed: `top()`/`rest()` remain purely risk-based pagination over
*all* findings (used only by the unchanged, `!baselineActive` code path); the new-vs-existing
partition and its own top-N slicing are computed locally inside
`MarkdownReportFormatter.appendBaselineAwareBody(...)`, since this is a rendering-only concern with
no other consumer.

## Design decision 4: `cmd/Main.java` wiring

Two new `@Option` fields, placed immediately after `--sarif-out` (before `--cache-dir`), following
the identical `defaultValue = ""` / blank-means-skip convention as every other path-based flag.

Two new package-private static factory methods, testable without picocli exactly like
`buildReachabilityStage`/`buildEnrichmentStage`/`buildProvider`/`buildOutputRenderers`:

```java
static BaselineStage buildBaselineStage(String baselineInPath) {
    if (baselineInPath == null || baselineInPath.isBlank()) {
        return findings -> findings; // identity: no baseline given
    }
    Baseline baseline = BaselineStore.read(Path.of(baselineInPath));
    Set<String> baselineIds = baseline == null ? null : baseline.findingIds();
    return findings -> BaselineDiffer.tag(findings, baselineIds);
}

static void writeBaselineIfRequested(RankedReport report, String baselineOutPath) {
    if (baselineOutPath == null || baselineOutPath.isBlank()) {
        return;
    }
    Set<String> ids = new LinkedHashSet<>();
    for (Finding f : report.findings()) {
        ids.add(f.id());
    }
    BaselineStore.write(Path.of(baselineOutPath), ids, Instant.now());
}
```

`buildBaselineStage` degrades gracefully all the way through: a missing/corrupt baseline file makes
`BaselineStore.read(...)` return `null` (never throwing), so `baselineIds` is `null`, so
`BaselineDiffer.tag(findings, null)` is the identity function — exactly the same outcome as
`--baseline-in` never having been supplied at all. No `try`/`catch` is needed in `Main` itself; the
never-fail contract is entirely satisfied one layer down, in `BaselineStore`/`BaselineDiffer`.

`writeBaselineIfRequested` is deliberately **not** an `OutputRenderer`. It is called as a plain
post-run step in `runPipeline()`, after `orchestrator.run(...)` returns its `RankedReport`. A
baseline file is not a report — nobody reads it, no dashboard renders it, its only consumer is a
*future Reachlayer run's own `--baseline-in` flag*. Modeling it as a renderer would misuse the
`OutputRenderer` SPI's semantics for something that isn't output in that sense.

## Design decision 5: `action.yml`

Two new optional inputs, `baseline-in` / `baseline-out`, threaded exactly like `sarif-out` was in
the immediately preceding pass. `baseline-out-path` output is added in the same currently-unwired
state as the pre-existing `report-path` and `sarif-path` outputs — a pre-existing gap this pass
does not fix, consistent with how the SARIF pass explicitly flagged (rather than silently fixed or
silently left inconsistent) the same gap for `sarif-path`. No `Dockerfile` change needed (every new
class lives inside the already-copied `core`/`cmd` directories). No `settings.gradle.kts` /
`build.gradle.kts` changes anywhere.

## Non-blocking guarantee (how this plan proves it)

- `BaselineStore.read(...)` never throws for any input, including `null`, a missing file, or
  malformed JSON — a dedicated test writes garbage bytes to a file and asserts `read(...)` returns
  `null` rather than propagating any exception.
- `BaselineStore.write(...)` never throws — a dedicated test passes a `null` path and asserts no
  exception and no file is created.
- `BaselineDiffer.tag(...)` is a pure function over already-in-memory data with no failure mode; a
  `null` `baselineIds` degrades to the identity function, tested directly.
- `Orchestrator.run(...)`'s existing `safeStage("baseline", ...)` wrapping means that even a
  hypothetical future regression in `BaselineDiffer`/`BaselineStage` that somehow threw a
  `RuntimeException` would be caught and logged, with `findings` passed through unchanged.
- `Main.buildBaselineStage(...)` never throws for any input string, because the failure mode is
  fully contained inside `BaselineStore.read(...)`.

## Reference: exact signatures this plan reads and extends (verified by direct reading)

```java
// core/src/main/java/dev/reachlayer/core/model/Finding.java (existing, unmodified accessors used)
public String id();
public Double riskScore(); // nullable, used only via RankedReport.of's existing sort — untouched

public static String stableId(String source, String rule, Location location, Component component)
// basis = source|rule|file:startLine|component.coordinate(); "-" + hex(basis.hashCode())
// deterministic across independent runs -> exactly what baseline diffing needs, already in place

// core/src/main/java/dev/reachlayer/core/model/RankedReport.java (unmodified by this plan)
public record RankedReport(List<Finding> findings, String repo, Instant generatedAt, int topN)
public static RankedReport of(List<Finding> findings, String repo, int topN) // sorts by riskScore desc
public List<Finding> top();  // findings.subList(0, topN) or all if fewer
public List<Finding> rest(); // remainder

// core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java (existing 7-arg constructor,
// kept unmodified; this plan adds a new 8-arg overload alongside it)
public Orchestrator(
        List<ScannerConnector> connectors,
        ReachabilityStage reachabilityStage,
        EnrichmentStage enrichmentStage,
        ScoringStage scoringStage,
        AdvisorStage advisorStage,
        List<OutputRenderer> outputRenderers,
        ReachlayerConfig config)
public RankedReport run(List<ScanSource> sources, String repoLabel)
private List<Finding> safeStage(String name, Supplier<List<Finding>> stage, List<Finding> fallback)
// catches RuntimeException, logs a warning, returns fallback -- every stage (including the new
// baseline stage) is wrapped in this exact same call

// core/src/main/java/dev/reachlayer/core/pipeline/ReachabilityStage.java (the pattern BaselineStage mirrors)
@FunctionalInterface
public interface ReachabilityStage { List<Finding> tag(List<Finding> findings); }

// core/src/main/java/dev/reachlayer/core/config/ReachlayerConfig.java, OutputConfig.java (unmodified)
public record ReachlayerConfig(ScoringWeights scoring, AdvisorConfig advisor, OutputConfig output)
public record OutputConfig(int topN, String commentMarker) // defaults: topN=5, "<!-- reachlayer:report -->"

// output/api/src/main/java/dev/reachlayer/output/api/MarkdownReportFormatter.java (current, full body
// extracted verbatim into the new appendUndiffedBody(...) private method; format(...) becomes a thin
// dispatcher)
public String format(RankedReport report, String marker)
private void appendTable(StringBuilder sb, List<Finding> findings, int rankStart) // reused unchanged

// cmd/src/main/java/dev/reachlayer/cli/Main.java (current signatures this plan extends)
@Option(names = "--sarif-out", defaultValue = "", description = "...") private String sarifOut;
private void runPipeline() throws IOException
static ReachabilityStage buildReachabilityStage(String classesDir) // the pattern buildBaselineStage mirrors

// enrich/epss/.../EpssClient.java, enrich/kev/.../KevClient.java (the on-disk cache-file JSON
// convention BaselineStore's DTO mirrors -- plain String date fields, no jsr310 registration)
private record CacheFile(String asOf, Map<String, CachedScore> scores) // EpssClient
private record CacheFile(String asOf, List<String> cveIds)             // KevClient
```
