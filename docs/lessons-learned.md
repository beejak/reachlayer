# Lessons learned

Running log of concrete, falsifiable things learned while building Reachlayer — not general advice,
only things that changed a decision or caught a real bug. Newest entries first.

## 2026-08-01 — A flagged research citation became a confirmed, reproduced bug

- **A claim sourced from a background research agent, however carefully hedged, is still just a
  claim until reproduced.** `docs/reachability-caveats.md` had, since the previous research pass,
  described SootUp's `invokedynamic`/lambda call-graph gap as "not yet reproduced against a local
  test fixture... treat as a flagged, high-priority research finding to validate." This pass built
  the fixture: `LambdaDispatchController.reachViaLambda()`, a genuine Spring MVC entry point that
  calls `LambdaVulnerableComponent.unsafeMethod()` through a `java.util.function.Supplier` lambda.
  The result confirmed the claim exactly — `ReachabilityTagger` tags the class `UNREACHABLE` despite
  it being unambiguously reachable at runtime. Cross-checking by inspecting
  `sootup.callgraph-1.1.2.jar`'s actual contents (no lambda/invokedynamic-handling class exists in
  it at all) confirmed *why*, not just *that*, independent of the fixture result.
- **A test that documents a known-wrong result on purpose needs a comment explaining why it isn't
  a bug in the test.** `ReachabilityTaggerFixtureIT#chaFailsToResolveCallEdgesThroughALambdaDispatchAConfirmedFalseNegative`
  asserts `UNREACHABLE` — the *wrong* answer from a runtime-behavior standpoint — as a deliberate
  regression/documentation test: if a future SootUp upgrade or custom invokedynamic edge resolver
  ever fixes this, this exact test will start failing, which is the signal needed to know the fix
  worked and the caveats doc needs updating. Without the comment explaining that inversion, a future
  reader (or agent) skimming test names could easily "fix" this test by asserting `REACHABLE`,
  silently erasing the regression-detection value.
- **Confirming a real gap doesn't obligate fixing it in the same pass — but it does obligate being
  honest about the size of the fix.** The actual fix (upgrade SootUp on the chance a newer version
  resolves this, or write a custom invokedynamic/lambda-metafactory edge resolver) is a genuine
  reachability-engine change, not a small patch, and attempting it opportunistically in the same
  pass that confirmed the gap would have risked a rushed, undertested change to the one component
  this project can least afford to get subtly wrong. Documenting the confirmed gap rigorously and
  scoping the fix as explicit future work was the right call here, same as the vendor-reachability
  entry below chose "build the mechanism" over "implement the unverifiable real integration."

## 2026-08-01 — Surfacing a vendor signal without ever letting it silently win

- **A flagged research finding ("we might be discarding a vendor-supplied reachability field")
  turned into a concrete mechanism, not a fix.** Closing PLAN.md risk #11 for real would mean
  verifying the actual field name/shape Black Duck Detect uses when
  `--detect.impact.analysis.enabled` is on — something this project cannot do without a real
  vendor export, which the no-real-vendor-data rule (`CONTRIBUTING.md`) forbids fetching. So the
  right scope for this pass wasn't "implement the real integration," it was "build the plumbing so
  that *if* a real field shows up with roughly this shape, the pipeline already knows what to do
  with it, and make that visible in the PR comment today using the synthetic shape this project
  invented." `Finding.vendorReachability()` is deliberately a second, separate field from
  `Finding.reachability()` — never a replacement, never merged into one value — because the whole
  point of surfacing it was to make disagreement between two signals visible, not to pick a winner.
- **A `toBuilder()`-based immutable model means a new field, once added to the builder/copy
  method, flows through every existing pipeline stage for free.** `vendorReachability` is set once
  by `BlackDuckConnector` at ingestion and needed zero changes anywhere in the pipeline between
  ingestion and `ReachabilityTagger` (enrichment, scoring, baseline stages all pass it through
  unmodified via `toBuilder()`) purely because every stage already builds on top of the previous
  `Finding` rather than constructing a new one from scratch. This is the same lesson as the
  `PipelineMetrics`/`Instant` entry below in spirit, but from the opposite direction: sometimes the
  existing design *already* generalizes correctly, and the only work needed is adding the field.
- **"Disagreement" and "inconclusive" are not the same finding, and conflating them would have
  been a smaller, worse feature.** When Reachlayer's own tag is a genuine `REACHABLE`/`UNREACHABLE`
  verdict and a vendor signal disagrees, that's an actionable conflict between two real analyses.
  When Reachlayer's own tag is `UNKNOWN` (call graph unavailable, component not observed, no
  signature), there was no real Reachlayer verdict to disagree with — the vendor's signal is just
  additional information filling a gap. `ReachabilityTagger.noteVendorDisagreement` words these two
  cases differently in `reachEvidence` on purpose; testing both cases separately
  (`ReachabilityTaggerFixtureIT` for the real-call-graph disagreement, `ReachabilityTaggerTest` for
  the inconclusive-own-analysis case) caught that the first draft's single wording made the
  inconclusive case read as a false claim of disagreement.

## 2026-08-01 — The evaluation CI job's first real run caught a bug manual testing missed

- **`./gradlew :<subproject>:run --args="build/out ..."` resolves `build/out` relative to the
  *subproject's* directory, not the repo root — a real bug that only surfaced on the evaluation
  job's actual first CI run**, never during local manual verification (the earlier "3 reachable, 2
  unreachable, 100 unknown, matched exactly" check ran the built jar directly, with a different
  working directory, not through `gradlew :fixtures:corpus-generator:run`). In CI, the corpus files
  landed under `fixtures/corpus-generator/build/evaluation-corpus/`, while the next step read from
  `build/evaluation-corpus/` at the repo root — silently ingesting 0 findings, an empty
  reachability distribution, and a correctly-firing sanity-check failure (not a false negative in
  the check itself — the check did exactly its job). Fixed by using `$GITHUB_WORKSPACE`-anchored
  absolute paths throughout the job's steps instead of paths relative to "wherever this step
  happens to run from." Lesson: a manual, in-process verification of a pipeline and a CI job that
  drives the same pipeline through a different invocation path (Gradle's `application` plugin `run`
  task vs. a plain `java -jar`) are not the same test — the exact command a CI job runs needs to be
  run for real at least once, not approximated by a locally-convenient equivalent, before trusting
  it's wired correctly.

## 2026-08-01 — Competitive research changed the pitch, not the roadmap

- **The most useful competitive-research finding was about vendors, not competitors.** Two
  background research agents dug into commercial ASPMs and OSS/vendor-native tooling
  (`docs/competitive-landscape-commercial-technical.md`, `docs/competitive-landscape-oss.md`).
  The single most actionable finding wasn't a competing product — it was that **Black Duck's own
  Detect scanner already ships native Java call-graph reachability** (`--detect.impact.analysis.enabled`),
  meaning the "unmodified" Black Duck export this project ingests may already carry a reachability
  verdict `BlackDuckConnector` currently discards. Flagged (not fixed) in `docs/connectors.md` and
  `PLAN.md` risk #11 — fixing it means parsing a field we don't even have a fixture for yet, and per
  this repo's own no-real-vendor-data rule (`CONTRIBUTING.md`), the fixture would need to be built
  synthetic-first before the parsing gap can be closed. Lesson: "layer, never replace" cuts both
  ways — it's not just about not overriding a scanner's *severity*, it's about not silently
  discarding a scanner's *own* enrichment fields either.
- **A positioning claim can be "literally true" and still misleading.** PLAN.md's original claim
  ("no OSS project combines reachability with Fortify/Black Duck ingestion") held up under direct
  GitHub search — genuinely true. But treating that as "our reachability is novel" would have been
  wrong: dep-scan/atom (usage-slicing) and Semgrep Supply Chain (dataflow/taint, with a public blog
  post explicitly critiquing CHA-only reachability's false-positive-on-"reachable" failure mode) are
  both more technically sophisticated than this project's CHA approach, and both exist today. Fixed
  by rewriting the PLAN.md §1 pitch to stop leading with "reachability novelty" and lead with
  "cross-scanner correlation + OSS + non-blocking PR-native delivery" instead — a narrower but
  actually-defensible claim. Lesson: when research contradicts a document's framing rather than its
  facts, the fix is rewriting the pitch, not just appending a caveat.
- **A caveats doc that only lists one failure direction is half a caveats doc.**
  `docs/reachability-caveats.md` documented false negatives (`unreachable` when actually reachable)
  in detail but said nothing about the opposite: CHA over-approximates, so it can tag something
  `reachable` when the runtime conditions to trigger it aren't actually met. Semgrep's own
  engineering blog makes exactly this critique of CHA-only tools. Added a new section rather than
  editing the existing one, since it's a distinct failure mode with a distinct (lower, for this
  project specifically, since reachability is additive-only) severity — conflating the two would
  have understated the asymmetry.

## 2026-08-01 — Baseline/diff mode, observability, evaluation pipeline, and a real bug found

- **A background architecture-review agent found a genuine correctness bug, not just latency
  nits.** `GitHubRestApiClient.listIssueComments` never paginated — it fetched only GitHub's
  default first page (30 comments). On any PR with more comments than that, Reachlayer's own
  marker comment could be invisible, so `GitHubPrCommentRenderer` would create a duplicate comment
  instead of upserting — silently defeating the project's own "single upserted comment, never
  spam" design goal. This class had **no dedicated unit test at all** before this was found; the
  only coverage was `GitHubPrCommentRendererTest`, which fakes the whole `GitHubApiClient`
  interface and never exercises this class's real HTTP/pagination logic. Fixed and verified
  against a real local `com.sun.net.httpserver.HttpServer` (JDK-builtin, no new dependency)
  simulating a multi-page response. Lesson: an interface-level fake in tests can hide that the
  *real* implementation behind it is completely untested — worth periodically checking "which
  concrete classes implementing this interface have zero direct tests," not just "is the interface
  covered."

- **Constructor overloading (not extending an existing signature) is the right call whenever a new
  optional stage has *multiple* existing call sites, not just one.** `output/sarif`'s
  `buildOutputRenderers` extension (previous session) had to update its one `MainWiringIT` call
  site because it added a parameter to an *existing* method. `Orchestrator`'s baseline-stage
  addition instead added a new 8-arg constructor overload alongside the untouched 7-arg one — zero
  changes needed to `OrchestratorTest`'s three pre-existing call sites. The deciding factor wasn't
  "is this cleaner in the abstract," it was "how many existing call sites would a signature change
  force me to touch" — more than one is the threshold where an overload beats extending.

- **An evaluation corpus that references real fixture classes (not just synthetic data) is what
  actually proves an engine works end-to-end.** Every other test in this repo either used the tiny
  5-finding golden-path fixture or passed an empty `--classes` (identity passthrough, always
  `unknown`). Building a larger synthetic corpus whose "anchor" findings deliberately name real
  classes in `fixtures:vulnerable-spring-app` — and then running the *actual built CLI jar*, not
  just an in-process test — produced the exact predicted reachability distribution (3 reachable, 2
  unreachable, 100 unknown) on the first try. This is a stronger proof than any number of
  unit-level assertions about `ReachabilityTagger` in isolation, because it exercises the real
  wiring a user's `--classes` flag goes through.

- **A one-line, "obviously correct" perf fix can still hide behind a subtle API design choice.**
  `KevClient.isKnownExploited(cve)` re-invoked `knownExploitedCves()` (a disk read + JSON parse)
  on every call, by design — the class intentionally re-checks cache staleness per call, which is
  correct for *that* class's contract. The fix wasn't to change `KevClient` (that would weaken a
  deliberate freshness guarantee); it was to hoist ONE call to the already-public
  `knownExploitedCves()` at the call site (`EnrichmentPipeline`) and check membership locally in
  the loop. Lesson: when an inefficiency is found inside a well-designed class, check whether the
  fix belongs at the call site instead of the class itself.

- **Jackson needs `jackson-datatype-jsr310` registered explicitly for `Instant` fields, even
  though the dependency is already declared.** `PipelineMetrics`'s `Instant startedAt/completedAt`
  fields threw `InvalidDefinitionException` on first serialization attempt in `MetricsWriterTest`
  — `core/build.gradle.kts` already declares `jackson-datatype-jsr310` as an `api` dependency, but
  nothing had ever registered the module on an `ObjectMapper` before (this is exactly the footgun
  `core.baseline.BaselineStore`'s design spec called out and deliberately avoided by using a plain
  `String` timestamp instead). `MetricsWriter` registers `JavaTimeModule` properly since its
  `Instant` fields are a genuine, deliberate part of the public model — the two designs aren't in
  tension, they're both correct for what each class actually needs.

## 2026-07-31 — SARIF output renderer (Phase 1, first item)

- **A test's `ObjectMapper` must mirror production's serialization config, or null-omission
  assertions lie.** `SarifReportBuilderTest` originally used a bare `new ObjectMapper()` to
  re-serialize `SarifModel.SarifLog` for assertions, while `SarifOutputRenderer` (production)
  configures `JsonInclude.Include.NON_NULL`. The bare mapper serialized an absent `region` as an
  explicit JSON `null` instead of omitting the field, so `node.at("/.../region").isMissingNode()`
  was false when it should have been true — a real failure, not a flaky test. Fix: the test's
  static `MAPPER` now applies the same `NON_NULL` inclusion as the renderer. Lesson: when a test
  re-parses a model's own serialized form to assert structure, match the *production* mapper
  config exactly, or the test is validating a different format than what ships.

- **This sandbox blocks live EPSS/KEV HTTP calls (`403` at the proxy tunnel)** — confirmed by
  running the built CLI for real, not just via fake `HttpFetcher`s in unit tests. This was the
  intended non-blocking-degradation path (PLAN.md §9 risk #7) exercising itself: `EpssClient`
  fell back to cache, `KevClient` fell back to an empty result, and the process still exited `0`
  and produced a complete, correctly-scored report and a valid SARIF file. Useful to know before
  assuming a manual end-to-end run "isn't testing anything real" just because it can't reach the
  internet — the graceful-degradation contract is exactly what such a run proves.

- **SARIF rule-id deduplication by CWE (not by CVE or per-finding) collapses unrelated CVEs that
  share a root cause into one GitHub Security-tab rule.** In the fixture run, `CVE-2021-44228`
  (Log4Shell) and `CVE-2019-12384` (Jackson polymorphic deserialization) both carry `CWE-502`
  (deserialization of untrusted data) and were correctly merged into a single
  `blackduck:CWE-502` rule with two results — this is desired grouping, not a collision bug, but
  it means "one rule per CVE" is the wrong mental model for this renderer; it's "one rule per
  underlying weakness class."

- **A read-only planning agent (no `Write`/`Edit` tools) cannot save its own output** — it can
  only return the full file contents as text in its final report. When delegating a "write a
  design spec and plan" task to such an agent, the orchestrating session must relay and save that
  text itself; don't assume the files exist on disk just because the agent reports paths it
  "wrote."

- Phase 0 (the MVP) was already fully implemented before this session started — 7,211 lines of
  Java, all modules wired end-to-end via `cmd`'s `Main`. Worth checking `git log` and actual
  module contents before assuming a `PLAN.md` roadmap item is unstarted; the roadmap doc lags
  implementation reality.
