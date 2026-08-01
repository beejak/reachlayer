# Architecture & network-design review

A research pass over the pipeline as actually implemented (not as documented), focused on
network design and concrete optimization opportunities. Ground truth is the code cited inline;
`PLAN.md` and `docs/architecture.md` are the design intent, cross-checked against, not restated.

This is written for whoever picks up Phase 1 hardening work next. It is deliberately honest about
which "optimizations" are not worth doing given Reachlayer's actual usage shape.

---

## 1. Current architecture summary (as implemented)

`cmd/src/main/java/dev/reachlayer/cli/Main.java` is the composition root. `Main.call()` runs
exactly once per CLI invocation, `Main.runPipeline()` builds one `Orchestrator`
(`core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java`) and calls `run(sources,
repoLabel)` synchronously, then the process exits. There is no server, no daemon, no request loop
— every "call point" described below happens at most once per CI job, for the lifetime of one JVM
process.

`Orchestrator.run` executes six stages as a strict sequential pipeline, each wrapped in
`timedStage(...)` (`Orchestrator.java:183-199`): reachability → enrichment → scoring → advisor →
baseline. Ingestion happens before timing starts. Every stage's `RuntimeException` is caught,
logged into `stageErrors`, and the stage's *input* is passed through unchanged as its output — so
a stage failure never removes or corrupts findings, it just skips that stage's transformation
(`Orchestrator.java:190-198`). Output rendering (`renderAll`, line 201) is a second, separate
per-renderer try/catch loop — one renderer's `OutputException`/`RuntimeException` doesn't stop the
others.

Two things worth calling out that the docs don't fully spell out:

- **The "pipeline" is one long synchronous call chain with no concurrency anywhere** — not
  between stages (enrichment can't start until reachability's `timedStage` call returns; baseline
  can't start until advisor's does), and not *within* a stage either (see §2). `PipelineMetrics`
  records this precisely: `stageDurationMs` is wall-clock per stage, summed serially into
  `totalDurationMs`.
- **Enrichment is itself a mini-pipeline of three independent clients composed only in `cmd`**
  (`cmd/src/main/java/dev/reachlayer/cli/EnrichmentPipeline.java`), not in `core`. `core` only
  knows about the `EnrichmentStage` functional interface; the actual EPSS/KEV/blast-radius
  composition — and therefore the opportunity to parallelize them — lives entirely in `cmd`,
  which is the layer that would need to change for most of the recommendations below.
- **`BlastRadiusAnalyzer`** (`enrich/blastradius`) makes no network call at all — it's pure
  heuristics over already-loaded `Finding` data (package/annotation/name pattern matching, ~100
  lines). It's listed in the "three enrich clients" for completeness but isn't part of the network
  surface.

Data/control flow, synthesized from actually reading `Orchestrator`/`Main`/`EnrichmentPipeline`
rather than re-drawing `docs/architecture.md`'s diagram:

```
Main.runPipeline()                                    (single JVM process, single run)
 ├─ ingest (sequential, per-connector, per-source)      — no network
 ├─ Orchestrator.run(sources, repoLabel)
 │   ├─ timedStage("reachability")                      — no network (SootUp, local .class files)
 │   ├─ timedStage("enrichment")  → EnrichmentPipeline.enrich()
 │   │     1. epssClient.lookup(allDistinctCves)         — ONE batched HTTP call (or 0 if cache-fresh)
 │   │     2. for each finding: kevClient.isKnownExploited(cve)   — 0 or 1 HTTP call total, but see §2
 │   │     3. for each finding: blastRadiusAnalyzer.analyze()     — no network
 │   ├─ timedStage("scoring")                            — no network, pure arithmetic
 │   ├─ timedStage("advisor")     → FixAdvisorService.advise()
 │   │     for i in [0, topNForLlm): sequential provider.suggest() call (Anthropic HTTP POST)
 │   │     for the rest: templated fallback, no network
 │   └─ timedStage("baseline")                           — no network, local JSON file
 ├─ renderAll(report)
 │     ConsoleOutputRenderer (no network) → SarifOutputRenderer (no network, if configured)
 │     → GitHubPrCommentRenderer (2-3 sequential HTTP calls, if configured)
 └─ writeBaselineIfRequested / writeMetricsIfRequested   — no network
```

---

## 2. Network design: every external call point

### 2.1 EPSS — `enrich/epss/src/main/java/dev/reachlayer/enrich/epss/EpssClient.java`

- **Endpoint:** `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...` (line 44, 124).
- **When it fires:** once per `Orchestrator.run`, from `EnrichmentPipeline.enrich` — but only for
  CVEs *not* already fresh in the same-day disk cache (`EpssClient.lookup`, lines 66-120).
- **Batching:** confirmed still batched as one call for every distinct CVE across the whole
  finding list — `EnrichmentPipeline.enrich` collects `List<String> cveIds` via `.distinct()`
  (line 39-43) before calling `epssClient.lookup(cveIds)` once (line 44); `EpssClient.lookup`
  itself further narrows to only the cache-miss subset (`missing`, lines 77-89) before making a
  *single* HTTP GET with all of them comma-joined into one query string. There is no per-finding
  or per-CVE HTTP call anywhere in this path.
- **Cache:** disk JSON at `<cacheDir>/epss-cache.json`, daily TTL keyed by a top-level `asOf` date
  string compared to `today.get()` (lines 73-74, 152-175). A cache hit for a CVE already recorded
  today skips the network entirely.
- **Failure mode:** verified as graceful. `fetchFromApi` throwing `IOException` is caught in
  `lookup` (lines 92-105): it logs a warning and falls back to whatever's in the stale cache for
  the missing CVEs, omitting any CVE with no cached data at all — it never throws out of
  `lookup()`. `docs/lessons-learned.md` records this was exercised for real (sandboxed proxy
  blocked the live call and the run still completed).
- **Timeout:** `JdkHttpFetcher` (same package) sets `connectTimeout(10s)` on the `HttpClient`
  builder and a **per-request `.timeout(30s)`** (`JdkHttpFetcher.java:16,27`). So EPSS does have an
  explicit request timeout — a hang is bounded to 30s, not indefinite.
- **Retry/backoff:** none. A single failed attempt (including a timeout) immediately falls back to
  cache. No retry loop exists anywhere in the repo (verified: no file matches `retry`/`backoff` in
  a repo-wide search).
- **TLS/auth:** plain HTTPS via the JDK's default trust store; no auth (EPSS is a free, no-auth
  API per PLAN.md §6). No custom `SSLContext` — relies on JDK defaults.

### 2.2 KEV — `enrich/kev/src/main/java/dev/reachlayer/enrich/kev/KevClient.java`

- **Endpoint:** `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (line 42) — the **entire** KEV catalog as one JSON file, not a per-CVE query (CISA's KEV feed has
  no per-CVE query parameter to begin with).
- **When it fires:** once per `Orchestrator.run`, but only if the disk cache's `asOf` isn't today
  (`knownExploitedCves`, lines 70-87).
- **Batching:** effectively already maximal — one fetch retrieves every known-exploited CVE ID at
  once, cached as a `Set<String>`. However, `EnrichmentPipeline.enrich` (line 50) calls
  `kevClient.isKnownExploited(cve)` **once per finding**, and each call re-invokes
  `knownExploitedCves()` (line 61), which re-reads and re-parses the on-disk cache file
  (`readCache()`, lines 110-122) from scratch every single time — there is no in-memory cache of
  the parsed `Set<String>` across calls within one run. This is not a network inefficiency (no
  extra HTTP calls result — the cache is fresh after the first fetch-and-write) but it is an
  unnecessary repeated-disk-I/O-plus-JSON-parse cost scaling with finding count, worth noting
  alongside the network items since it lives in the same client.
- **Cache:** disk JSON at `<cacheDir>/kev-cache.json`, daily TTL, same shape/pattern as EPSS.
- **Failure mode:** verified graceful — `fetchFromApi()`'s `IOException` is caught in
  `knownExploitedCves()` (lines 82-86), falling back to stale cache, or `Set.of()` if there's no
  cache at all. Never throws.
- **Timeout:** same `JdkHttpFetcher` as EPSS (separate module-local copy of the same class, not a
  shared dependency) — 10s connect / 30s request timeout.
- **Retry/backoff:** none, same as EPSS.
- **TLS/auth:** plain HTTPS, no auth. Note this is CISA's own `cisa.gov` static file host, not a
  dedicated API endpoint — no rate-limit contract is documented or handled either way, but a single
  daily GET is well within any reasonable use.
- **Documented scope gap:** the class-level Javadoc (lines 23-26) explicitly notes PLAN.md
  describes KEV refresh as a "daily diff," but this implementation does a full refetch-and-replace
  once a day rather than an incremental diff — called out as a deliberate Phase 1 follow-up, not
  an oversight.

### 2.3 GitHub REST API — `output/github-pr/src/main/java/dev/reachlayer/output/githubpr/GitHubRestApiClient.java` + `GitHubPrCommentRenderer.java`

- **Endpoints used** (lines 21-27, 64-105): `GET /repos/{owner}/{repo}/issues/{prNumber}/comments`,
  then either `PATCH /repos/{owner}/{repo}/issues/comments/{commentId}` or
  `POST /repos/{owner}/{repo}/issues/{prNumber}/comments`.
- **When it fires:** once per `Orchestrator.run`, only if `--post-pr-comment=true` (default) and
  `GITHUB_REPOSITORY`/`GITHUB_PR_NUMBER`/`GITHUB_TOKEN` are all present
  (`GitHubPrCommentRenderer.fromEnvironment`, `Main.buildOutputRenderers` lines 255-261 catches
  `IllegalStateException` and just skips the renderer, logged at `info`, if env vars are missing).
- **Batching/call count:** always 2 calls (list, then update-or-create) per run — this is
  inherently sequential (you must know whether a marker comment exists before deciding
  update-vs-create), not a batching opportunity.
- **Pagination — a real gap:** `listIssueComments` (lines 65-83) does a single unparameterized
  `GET .../comments` with no `?page=`/`?per_page=` handling and no follow-up requests for
  subsequent pages. GitHub's default page size for this endpoint is 30. On a PR with more than 30
  existing comments where the Reachlayer marker comment isn't on the first page, `render()`
  (`GitHubPrCommentRenderer.java:104-108`) will not find `target`, fall through to `createComment`
  (line 113), and **post a duplicate comment instead of upserting** — silently defeating the
  "single upserted comment, never spam" design goal (PLAN.md §6, `docs/architecture.md` line 30).
  This never crashes the build (any downstream `IOException` still degrades to a logged
  `OutputException`), but it is a functional correctness gap, not just a latency one.
- **Rate-limit/403/429 handling — not distinguished:** `requireSuccess` (lines 125-132) treats
  every non-2xx status identically — it wraps any status outside `[200,300)` into a generic
  `IOException` with the truncated response body. A `403` (secondary rate limit / permission
  issue) or `429` (primary rate limit, with a `Retry-After` header GitHub does send) is handled
  exactly like a `404` or `500`: logged, swallowed by `Orchestrator`'s renderer try/catch, no
  distinct backoff or retry. Given "never fail the build," swallowing is the *correct* end
  behavior; the gap is that a transient rate-limit could be trivially recovered from (one retry
  after `Retry-After`) but instead silently produces "no PR comment this run" with no visibility
  beyond a log line (metrics do record it in `outputRendererErrors`, at least).
- **Timeout:** `requestBuilder` sets a **30s per-request timeout** (line 109) and the underlying
  `HttpClient` has a 10s connect timeout (line 40) — explicit, same pattern as EPSS/KEV/Anthropic.
- **Retry/backoff:** none.
- **TLS/auth:** HTTPS + `Authorization: Bearer <GITHUB_TOKEN>` header (line 110), token sourced
  from the `GITHUB_TOKEN` env var GitHub Actions injects automatically. No custom TLS config.

### 2.4 Anthropic API (fix advisor) — `advisor/providers/anthropic/src/main/java/dev/reachlayer/advisor/providers/anthropic/AnthropicLlmProvider.java` + `JdkAnthropicHttpClient.java`

- **Endpoint:** `POST https://api.anthropic.com/v1/messages` (line 27), only when `isAvailable()`
  is true (`ANTHROPIC_API_KEY` set, line 82-84) — otherwise `Main.buildProvider` wires
  `NoopLlmProvider` instead (`Main.java:246`), which never touches the network.
- **When it fires, and batching granularity:** `FixAdvisorService.advise`
  (`advisor/api/src/main/java/dev/reachlayer/advisor/api/FixAdvisorService.java:55-68`) loops over
  **every** finding in ranked order and calls `suggestViaProvider` (one real LLM HTTP call) for
  only the first `config.topNForLlm()` (default 5, `AdvisorConfig.defaults()`), templating
  everything else. This is exactly the PLAN.md §9 risk 5 policy ("only call the LLM for
  top-ranked findings") and it is implemented correctly. **These top-N calls are strictly
  sequential** — the `for` loop (line 61) calls `suggestViaProvider(finding)` and blocks on its
  result before moving to `i+1`; there is no batching of multiple findings into one prompt, and no
  concurrent dispatch of the up-to-5 independent calls.
- **Failure mode:** verified graceful at two levels. Per-call: `AnthropicLlmProvider.suggest`
  wraps its `IOException` into an unchecked `RuntimeException` (lines 104-106) — by its own
  Javadoc (lines 21-24) it deliberately does *not* catch and fall back itself, leaving that to the
  caller. `FixAdvisorService.suggestViaProvider` (lines 70-90) is that caller: it catches
  `RuntimeException` from *any* cause (network failure, malformed JSON, rate limit, `provider`
  returning `null`) and falls back to `templatedFallback(finding)` for just that one finding,
  logging a warning — one bad LLM call never aborts the batch or the run.
- **Timeout:** `JdkAnthropicHttpClient` sets a 10s connect timeout and a **60s per-request
  timeout** (`JdkAnthropicHttpClient.java:17,28`) — longer than the other three clients'
  30s, appropriate for LLM generation latency, and still bounded (a hang cannot exceed 60s per
  call, ~300s worst case for 5 sequential calls that each hang to their timeout).
- **Retry/backoff:** none.
- **TLS/auth:** HTTPS + `x-api-key` / `anthropic-version` headers (lines 92-95), API key from
  `ANTHROPIC_API_KEY` env var. No custom TLS config.

### Summary table

| Client | Batched? | Cached? | Timeout | Retry | Failure mode |
|---|---|---|---|---|---|
| EPSS | Yes — one call for all distinct CVEs | Yes, daily disk TTL | 10s connect / 30s request | None | Graceful: stale cache → empty |
| KEV | Yes — whole catalog, one call | Yes, daily disk TTL | 10s connect / 30s request | None | Graceful: stale cache → empty set |
| GitHub PR | N/A (inherently 2 sequential calls); **no pagination** on list | No | 10s connect / 30s request | None | Graceful (renderer-level), but no 403/429-specific handling, and pagination gap risks duplicate comments |
| Anthropic | No — top-N sequential, one call per finding | No (by design — LLM output isn't meant to be a static cache without a cache-key strategy) | 10s connect / 60s request | None | Graceful per-finding fallback to template |

---

## 3. Concrete optimization opportunities

Each entry: what, why, rough shape, risk/tradeoff.

### 3.1 Parallelize EPSS and KEV fetches
- **What:** `EnrichmentPipeline.enrich` currently calls `epssClient.lookup(cveIds)` fully, then
  loops calling `kevClient.isKnownExploited(cve)` per finding. EPSS and KEV are independent — EPSS
  doesn't need KEV's result or vice versa.
- **Why it matters:** Latency, not cost — both are free APIs. On a cache-miss day, this saves
  roughly the smaller of the two calls' duration (EPSS and KEV would run concurrently instead of
  serially). In the common case (both cache-fresh), there's no network at all and this change buys
  nothing — the benefit only exists on the (rare, once-daily) cache-refresh day.
- **Shape:** kick off `CompletableFuture.supplyAsync(() -> epssClient.lookup(cveIds))` and, in
  parallel, pre-warm KEV's cache with one `kevClient.knownExploitedCves()` call (see 3.2 below —
  this also fixes the redundant-reads problem), then `.join()` both before the per-finding loop.
- **Risk/tradeoff:** low risk, small win. Needs a shared executor or ad hoc thread — trivial at
  this scale (two futures, joined immediately), but it's still one more thing to get right in
  error propagation (a `CompletionException` wrapping needs unwrapping to preserve the existing
  graceful-degradation contract per finding).

### 3.2 Fix the KEV per-finding redundant cache reads
- **What:** Call `kevClient.knownExploitedCves()` **once** at the top of
  `EnrichmentPipeline.enrich`, store the resulting `Set<String>`, and check membership locally in
  the per-finding loop, instead of calling `isKnownExploited(cve)` (which calls
  `knownExploitedCves()` → `readCache()` → disk read + JSON parse) once per finding.
- **Why it matters:** Not a network fix (no extra HTTP calls happen today either way) — it's a
  compute/IO fix. For a large finding set (thousands, per PLAN.md's stated backlog sizes), this
  currently does thousands of redundant disk reads + JSON deserializations of the same
  never-changing-within-a-run KEV set. Cheap to fix, real but modest win at realistic finding
  counts (disk cache files are small).
- **Shape:** one-line change in `EnrichmentPipeline.enrich`: hoist
  `Set<String> kevCves = kevClient.knownExploitedCves();` next to the existing `epssByCve` line,
  then replace `kevClient.isKnownExploited(cve)` with `cve != null && kevCves.contains(cve)`.
  `KevClient.isKnownExploited` itself could also gain an internal memoized/instance-cached set, but
  that changes the class's contract (it currently intentionally re-checks staleness on every call)
  — the caller-side fix is simpler and doesn't touch `KevClient` at all.
- **Risk/tradeoff:** essentially free, "just do it." No behavior change, no new failure modes.

### 3.3 Parallelize the top-N Anthropic LLM calls
- **What:** `FixAdvisorService.advise`'s sequential `for` loop over the top-`topNForLlm` (default
  5) findings could dispatch those calls concurrently instead of one-at-a-time.
- **Why it matters:** Latency. Each call can take up to the 60s timeout in the worst case;
  sequential worst case is `topNForLlm * 60s` (5 min), concurrent worst case is ~60s. Even in the
  typical case (a few seconds per call), 5 sequential round-trips to `api.anthropic.com` adds up to
  several seconds of pure network latency that concurrency would collapse to one round-trip's worth.
- **Shape:** replace the loop body for `i < topN` with a list of
  `CompletableFuture.supplyAsync(() -> suggestViaProvider(finding), executor)`, then `.join()`
  each in order when assembling `result` (order must be preserved — findings are already
  risk-ranked and the output list's order matters for `RankedReport`). A small fixed-size executor
  (e.g. `Executors.newFixedThreadPool(Math.min(topN, 5))`) is enough; no need for anything fancier
  given `topNForLlm` is a small, bounded number by design (PLAN.md §9 risk 5 — "only top-ranked
  findings, not all").
- **Risk/tradeoff:** low-medium. Needs care that `suggestViaProvider`'s existing try/catch-and-
  fallback-to-template semantics are preserved per-future (already isolated per call, so this
  should be mechanical), and that the executor is shut down cleanly (this is a one-shot CLI
  process, so even skipping a graceful shutdown is low-risk, but doing it right costs nothing).
  Also consider: Anthropic likely has its own account-level rate limits — 5 concurrent calls is
  very unlikely to trip them, but this is worth a one-line comment/doc note if raising
  `topNForLlm` well beyond 5 in some deployment's `reachlayer.yml`.

### 3.4 Add explicit timeouts — **already done, verify only**
- **What was asked:** check if any outbound call is missing an explicit timeout.
- **Finding:** all four HTTP clients (`epss`/`kev`'s shared-pattern `JdkHttpFetcher`,
  `GitHubRestApiClient`, `JdkAnthropicHttpClient`) already set both a `connectTimeout(10s)` on the
  `HttpClient` and a per-request `.timeout(...)` (30s for EPSS/KEV/GitHub, 60s for Anthropic). This
  is correctly done already — no missing-timeout gap exists in the current code. **No action
  needed here**; this is worth stating explicitly so a future contributor doesn't "fix" a
  non-problem.

### 3.5 Retry/backoff policy — deliberate absence, mostly the right call, with one exception
- **What:** there is no retry logic anywhere (verified by a repo-wide search — zero matches for
  `retry`/`backoff`).
- **Why this is mostly fine as-is:** EPSS and KEV already have a *strictly better* fallback than a
  retry would provide — a same-day disk cache. A failed EPSS/KEV call today means "serve
  yesterday's (or the day's own) cached data, degrade gracefully" — adding a retry here would only
  add latency to a CI job for a marginal chance of getting a live answer instead of a
  (already-acceptable, by design) day-old one. **Not worth adding.**
- **Where a retry might actually help:** the GitHub PR comment upsert and, to a lesser extent, the
  Anthropic call — both are single-shot, no-cache operations where a transient failure (a `502`
  from GitHub, a momentary Anthropic overload) currently means "no PR comment this run" /
  "templated fallback instead of an LLM suggestion this run" with zero recovery chance. A single
  retry-once-after-a-short-backoff (not a full exponential-backoff library) for these two clients
  specifically would trade a few seconds of extra worst-case latency for meaningfully better
  delivery odds on the *one* user-facing artifact (the PR comment) and the *one* highest-value
  enrichment (LLM fix text for the top findings). This is a "needs a design discussion" item, not
  a "just do it" — see §4.
- **Where a retry would be actively wrong:** none of the "never fail the build" guarantees change
  either way (both success and failure paths already degrade gracefully) — so this is purely a
  quality-of-delivered-output question, not a reliability-of-the-build question. Don't conflate the
  two when deciding priority.

### 3.6 HTTP client reuse / connection pooling — already fine, given the usage shape
- **What was asked:** check whether each client opens a fresh connection per call.
- **Finding:** each of the four HTTP clients constructs exactly one `java.net.http.HttpClient`
  instance per `EpssClient`/`KevClient`/`GitHubRestApiClient`/`AnthropicLlmProvider` construction
  (all via `HttpClient.newBuilder()...build()` in the respective `Jdk*` classes), and that same
  instance is reused for every `.fetch()`/`.post()` call made through it for the life of the
  process. The JDK `HttpClient` does connection pooling/keep-alive internally per client instance
  by default — so within, e.g., the 5 sequential Anthropic calls in one run, connections to
  `api.anthropic.com` are already eligible for reuse; same for the 2 GitHub calls to
  `api.github.com`.
- **Why this isn't worth "fixing" further:** Reachlayer is a **one-shot CLI process that runs
  once per CI invocation and exits** (§1) — there is no process-lifetime long enough for
  connection-pool warmup/keep-alive tuning to matter the way it would in a long-running service.
  EPSS and KEV each make at most one call per run to two different hosts, so there's nothing to
  pool across calls to the same host beyond what already happens implicitly. Sharing a single
  `HttpClient` instance across all four clients (EPSS/KEV/GitHub/Anthropic) would save at most the
  cost of constructing 3 extra `HttpClient` objects (cheap) and would gain nothing from pooling,
  since all four target different hosts anyway. **Not worth doing** — flagged explicitly as an
  "over-engineering for this usage shape" item, not a missed opportunity.

### 3.7 GitHub REST client: pagination and rate-limit handling
- **What:** two related gaps in `GitHubRestApiClient.listIssueComments` (see §2.3): (a) no
  pagination, so a marker comment beyond the first 30 comments on a PR is invisible, causing a
  duplicate comment instead of an upsert; (b) `403`/`429` treated identically to any other
  non-2xx status, so no `Retry-After`-aware backoff is possible even if one were added.
- **Why it matters:** (a) is a correctness bug under a realistic condition (any PR with an active
  discussion thread + Reachlayer running on every push can accumulate >30 comments over the PR's
  lifetime even without other bots) — it directly undermines the "single upserted comment, never
  spam" design goal stated in `docs/architecture.md`. (b) matters less on its own (see 3.5) but is
  a prerequisite for doing 3.5's optional GitHub retry well.
- **Shape:** (a) loop `GET .../comments?page=N&per_page=100` until a page returns fewer than
  `per_page` results, accumulating all comments before searching for the marker — bounded, since
  PR comment counts are not adversarially large. (b) branch `requireSuccess` on status `403`/`429`
  distinctly (check for a `Retry-After` header or GitHub's `x-ratelimit-reset` header) versus other
  4xx/5xx, at minimum to log a clearer diagnostic even without adding a retry.
- **Risk/tradeoff:** (a) is low-risk, mechanical, and closes a real (if edge-case) correctness gap
  — recommend prioritizing this over the latency-oriented items above precisely because it's a
  correctness fix, not a performance one. (b) is low-risk and small, but only valuable if paired
  with 3.5's GitHub retry — doing it alone just improves a log message.

### 3.8 Incremental call-graph construction (IncCHA) — PLAN.md Phase 1 item, compute not network
- **What:** `PLAN.md` §5 Phase 1 and §9 risk 3 already flag "incremental call-graph construction
  (IncCHA-style graph patching)" as a planned CI-speed optimization. `CallGraphBuilder.build`
  (`reachability/src/main/java/dev/reachlayer/reach/callgraph/CallGraphBuilder.java`) currently
  does a full from-scratch CHA construction every run (`buildOnce`, lines 72-91) — no persistence
  or reuse of a prior run's graph.
- **Why it matters, and why it's adjacent to (not itself) network optimization: this is the
  dominant cost center in the pipeline** on any codebase big enough to matter — `PLAN.md` §9 risk 3
  explicitly frames "1-8 hour scan friction" as "the very problem we're solving," and unlike the
  EPSS/KEV/GitHub/Anthropic calls (bounded by explicit timeouts to tens of seconds total), call
  graph construction has no such bound today. `PipelineMetrics.stageDurationMs["reachability"]`
  is exactly the instrumentation that would surface this in practice once run against a real
  (non-fixture-sized) codebase.
- **Shape (not attempted here — this is a design-level Phase 1 item, correctly still open):**
  persist a serialized graph + a content hash of the analyzed `.class` files/entry points between
  runs; on a re-run, diff which classes changed and patch only the affected subgraph rather than
  rebuilding from `JavaView` up. This is a nontrivial SootUp-specific design effort, not a
  small patch — correctly scoped as its own Phase 1 roadmap item rather than folded into this
  review's smaller items.
- **Risk/tradeoff:** high effort, high payoff on large codebases; effectively zero payoff on the
  current synthetic fixtures. Not a "just do it" — it's the single most consequential item in this
  document, but exactly because of that it warrants its own design spec, not a quick PR.

### 3.9 EPSS/KEV cache TTL tuning
- **What was asked:** whether the current daily TTL for both is well-tuned.
- **Finding:** EPSS is genuinely refreshed daily upstream (PLAN.md §6, confirmed by the client's
  own Javadoc), so a daily TTL is already the correct match to the upstream refresh cadence — there
  is no staleness to trade off by shortening it, and lengthening it would risk missing a real
  daily update. KEV has no push feed and is a low-frequency-changing catalog in practice, so a
  daily TTL is a reasonable, conservative default there too — CISA doesn't publish updates on a
  fixed schedule, so more frequent polling would mostly just be wasted requests to a free public
  feed the project doesn't control the availability contract for. **No change recommended** on TTL
  values themselves; both already match their upstream's actual refresh cadence documented in
  PLAN.md §9 risk 7. The only real KEV gap is the "full refetch instead of incremental diff" one
  already self-documented in `KevClient`'s Javadoc (§2.2) — that's a Phase 1 item, not a TTL
  problem.

---

## 4. Prioritized recommendations

Ranked by impact vs. effort, with an explicit stance on whether each is worth doing *for a tool
that runs once per CI invocation, not as a hot-path service* — several plausible-sounding
"optimizations" are called out as not worth it given that usage shape.

### Just do it (low effort, clear win, low risk)
1. **§3.2 — Fix the KEV per-finding redundant cache reads.** One-line change in
   `EnrichmentPipeline.enrich`, no behavior change, removes an O(findings) redundant disk-read+parse
   pattern. Highest ratio of benefit to effort in this whole review.
2. **§3.7(a) — GitHub comment-list pagination.** This is the one item in this document that's a
   correctness bug, not a performance nit — on a long-lived, active PR, Reachlayer can currently
   start spamming duplicate comments instead of upserting one, silently defeating its own stated
   design goal. Fix before the parallelization items below; it's more likely to actually bite a
   real user.
3. **§3.1 — Parallelize EPSS + KEV fetches.** Small, safe, real (if modest) latency win on
   cache-miss days. Natural to bundle with §3.2 since both touch the same few lines of
   `EnrichmentPipeline`.
4. **§3.3 — Parallelize the top-N Anthropic calls.** Bounded scope (at most `topNForLlm`,
   default 5, concurrent calls), meaningful worst-case latency reduction (up to 5x on the advisor
   stage specifically), existing per-call error isolation makes this mechanical to parallelize
   safely.

### Needs a design discussion first
5. **§3.5 — A narrow, single-retry policy for the GitHub PR comment upsert and the Anthropic
   call specifically** (not a general retry library, and explicitly *not* for EPSS/KEV, which
   already have a strictly better cache-based fallback). Worth discussing because it's a real
   delivery-quality improvement, but it touches failure-handling code paths that are currently
   simple and well-tested (`docs/success-criteria.md` explicitly tests the graceful-degradation
   contract) — any change here should be scoped carefully so it doesn't regress the "never fail
   the build" guarantee or the tested fallback behavior. Pair with §3.7(b)'s 403/429-aware status
   handling if pursued.
6. **§3.8 — Incremental call-graph construction (IncCHA).** Already correctly scoped as its own
   Phase 1 roadmap item in `PLAN.md`. This review's finding is simply: it remains the single
   highest-leverage performance item in the whole pipeline for any real (non-fixture) codebase,
   and nothing here should be read as suggesting the smaller network items above are a substitute
   for it. It needs its own design spec (persistence format, invalidation strategy, SootUp API
   surface for incremental graph patching), not a quick patch.

### Not worth it, given this tool's actual usage pattern
7. **Any HTTP connection-pool/keep-alive tuning beyond what the JDK `HttpClient` already does by
   default (§3.6).** Reachlayer is not a long-running service — it's a CLI process invoked once
   per CI job that makes at most a handful of HTTP calls total (1 EPSS, 1 KEV, up to 5 Anthropic,
   2-3 GitHub) to four different hosts, then exits. There is no warm connection pool to benefit
   from reusing across runs, and no request volume within a single run large enough for pooling
   tuning to matter. Time spent here would be pure over-engineering relative to this tool's actual
   deployment shape.
8. **A general-purpose retry/backoff library for every outbound call, including EPSS/KEV.**
   EPSS and KEV already degrade to a same-day (or stale) disk cache on any failure — a strictly
   better outcome than a retry, at no latency cost. Adding retries here would only slow down CI
   runs for a marginal, low-value chance of a live answer instead of an already-acceptable cached
   one. If a retry policy is added at all (item 5 above), it should be scoped narrowly to the two
   no-cache, single-shot calls (GitHub comment upsert, Anthropic), not applied uniformly.
9. **Shortening the EPSS/KEV cache TTL below one day "for freshness."** Both upstreams already
   publish on (at most) a daily cadence; a shorter TTL would only add load to two free public APIs
   the project doesn't control the availability SLA of, for data that isn't actually updated more
   often upstream. See §3.9.

---

## 5. What's already done right (say so explicitly, per review instructions)

- EPSS batching (§2.1) — already correct, one call for every distinct CVE, verified in code.
- KEV whole-catalog fetch (§2.2) — already correct, no per-CVE network calls.
- All four HTTP clients already have explicit connect + request timeouts (§3.4) — no hung-call
  risk exists today at the HTTP layer.
- Every network client already degrades gracefully on failure — EPSS/KEV to cache, GitHub/
  Anthropic to a logged, swallowed error that never propagates past `Orchestrator`'s per-stage/
  per-renderer try-catch. This is exhaustively tested per `docs/success-criteria.md` and was
  independently verified against a real (proxy-blocked) network failure per
  `docs/lessons-learned.md`.
- The top-N-only LLM call policy (PLAN.md §9 risk 5) is implemented exactly as designed —
  verified in `FixAdvisorService.advise`.
