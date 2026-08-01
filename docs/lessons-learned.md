# Lessons learned

Running log of concrete, falsifiable things learned while building Reachlayer — not general advice,
only things that changed a decision or caught a real bug. Newest entries first.

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
