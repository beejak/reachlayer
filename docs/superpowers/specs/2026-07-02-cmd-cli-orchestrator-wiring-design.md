# `cmd` CLI wiring — design spec

**Date:** 2026-07-02
**Status:** approved (informal — see conversation), proceeding to implementation plan

## Context

Reachlayer's pipeline modules (`connectors`, `reachability`, `enrich`, `scoring`, `advisor`,
`output`) are all implemented and independently tested. `core`'s `Orchestrator`
(`core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java`) already wires the
five pipeline stages together and is itself unit-tested (`OrchestratorTest`) — an earlier
survey of this repo incorrectly reported it as missing; it is not.

The actual gap: the `cmd` module has a fully-specified `build.gradle.kts` (depends on every
other module, fixes `application.mainClass = "dev.reachlayer.cli.Main"`, configures a
`shadowJar` task) but contains **zero source files**. `README.md`'s Quickstart section and
`action.yml`'s Docker `args:` list both already describe a CLI contract that nothing
implements yet. Additionally, `enrich:epss`, `enrich:kev`, and `enrich:blastradius` are three
independent classes with no shared `EnrichmentStage` implementation — `cmd` is the only module
that depends on all three, so the composition belongs there.

## Goal

Implement `dev.reachlayer.cli.Main` (and one small supporting class) so that:
1. `./gradlew :cmd:shadowJar` produces a runnable fat jar per the README Quickstart.
2. The exact CLI flags `action.yml` already invokes are implemented, so the Docker
   GitHub Action becomes runnable as specified.
3. Running the jar against `fixtures/sample-fpr/audit.fvdl` +
   `fixtures/sample-bdio/scan.json` (+ optionally `fixtures/vulnerable-spring-app`'s
   compiled classes for reachability) exercises the full pipeline end-to-end and produces a
   rendered Markdown report (console and/or `--out` file), proving PLAN.md §10 steps 6–8 are
   complete.

## Non-goals

- No changes to `core`, `connectors`, `reachability`, `enrich`, `scoring`, `advisor`, or
  `output` — all of their public APIs are already sufficient to wire this CLI (verified by
  reading every relevant class's constructor/method signatures directly).
- No new SPI, no new config fields beyond one additive CLI flag (`--cache-dir`) that
  `action.yml` doesn't reference and therefore can't break.
- No live-network integration test. EPSS/KEV network calls are exercised only via fake
  `HttpFetcher`s in tests, consistent with every other module's existing test style.

## CLI contract

Flags below reconcile README.md's Quickstart example with `action.yml`'s `args:` list — both
already exist and describe the same contract from two angles; this doc is the merge, not a new
design.

| Flag | Type | Default | Behavior |
|---|---|---|---|
| `--fortify` | path | blank | Fortify FVDL/FPR export. Blank ⇒ no Fortify source ingested. |
| `--blackduck` | path | blank | Black Duck JSON/BDIO export. Blank ⇒ no Black Duck source ingested. |
| `--repo` | path | `.` | Repo root, passed to `ContextBuilder` for code-snippet retrieval. Also used as the `RankedReport` repo label when `GITHUB_REPOSITORY` is unset. |
| `--classes` | path | blank | Compiled `.class` directory or jar for reachability analysis. Blank ⇒ reachability stage is the identity function (findings keep their constructor default: `UNKNOWN` / "not analyzed"). |
| `--config` | path | blank | `reachlayer.yml` path. Blank ⇒ `ReachlayerConfig.defaults()`. |
| `--out` | path | blank | Also write the rendered Markdown report to this file. Blank ⇒ console-only. |
| `--post-pr-comment` | boolean | `true` | Attempt a GitHub PR comment upsert (see below for the conditions under which this is actually attempted). |
| `--cache-dir` *(new, additive)* | path | `.reachlayer/cache` | Disk cache directory shared by the EPSS and KEV clients. Not referenced by `action.yml`, so its default silently applies there. |

`action.yml` always passes every flag, e.g. `--fortify=` when the corresponding Action input is
empty. Blank string is normalized to "not provided" for every path flag — never an error.

## Wiring

New class `dev.reachlayer.cli.EnrichmentPipeline implements EnrichmentStage`:
- Constructor takes an already-constructed `EpssClient`, `KevClient`, `BlastRadiusAnalyzer`.
- `enrich(findings)`: collects the distinct first-CVE-per-finding across the whole batch,
  calls `EpssClient.lookup(...)` once, then for each finding attaches `epss` (from the batch
  lookup, or `null`), `kev` (`KevClient.isKnownExploited(...)`), and `blastRadius`
  (`BlastRadiusAnalyzer.analyze(finding)`). Returns a new list in the same order; never mutates
  input, matching every other stage's contract.

`dev.reachlayer.cli.Main implements Callable<Integer>` (picocli):
1. Load config: `ConfigLoader.load(configPath)` if `--config` non-blank, else
   `ConfigLoader.loadDefaults()`.
2. Build `List<ScanSource>` from non-blank `--fortify` / `--blackduck`.
3. `connectors = List.of(new FortifyConnector(), new BlackDuckConnector())` — always both;
   `ScannerConnector.supports(...)` and the source list itself already gate what's actually used.
4. `reachabilityStage`: `--classes` blank ⇒ `findings -> findings`; otherwise
   `new ReachabilityTagger(Path.of(classes), List.of(new ComponentLevelSignatureSource()))`.
5. `enrichmentStage = new EnrichmentPipeline(new EpssClient(new JdkHttpFetcher(), cacheDir), new KevClient(new JdkHttpFetcher(), cacheDir), new BlastRadiusAnalyzer())`.
   (Note: `enrich.epss.HttpFetcher`/`JdkHttpFetcher` and `enrich.kev.HttpFetcher`/`JdkHttpFetcher`
   are separate same-named classes in different packages — imported fully qualified as needed
   in `Main`, no clash.)
6. `scoringStage = findings -> new RiskScorer().score(findings, config.scoring())`.
7. Provider: `"anthropic".equals(config.advisor().provider())` ⇒
   `AnthropicLlmProvider.fromEnvironment()`, else `new NoopLlmProvider()`.
8. `advisorStage = new FixAdvisorService(provider, config.advisor(), new ContextBuilder(), repoPath)`.
9. `outputRenderers`: always `new ConsoleOutputRenderer(System.out, outFileOrNull)`.
   Additionally, when `--post-pr-comment=true`, attempt
   `GitHubPrCommentRenderer.fromEnvironment(GitHubRestApiClient.fromEnvironment())` inside a
   try/catch on `IllegalStateException` (both `fromEnvironment()` methods throw this if
   `GITHUB_TOKEN`/`GITHUB_REPOSITORY`/`GITHUB_PR_NUMBER` are missing/malformed) — log a warning
   and skip on failure rather than aborting. This is the one behavior not literally spelled out
   by README/action.yml; it follows directly from PLAN.md principle 1 ("never fail or block the
   build").
10. `repoLabel = nonBlank(System.getenv("GITHUB_REPOSITORY"), repoPathString)`.
11. `new Orchestrator(connectors, reachabilityStage, enrichmentStage, scoringStage, advisorStage, outputRenderers, config).run(sources, repoLabel)`.
12. The whole body of `call()` is wrapped in try/catch(Exception); on any uncaught failure, log
    at ERROR and return `0` — never fail the build. Picocli's own exit code for malformed
    CLI arguments (parsed before `call()` runs) is untouched — that's a legitimate usage error,
    not a pipeline failure.

## Testing

- `EnrichmentPipelineTest` (new, `cmd`): fake `HttpFetcher`s for both `EpssClient` and
  `KevClient` (same pattern `enrich:epss`'s/`enrich:kev`'s own tests already use) — asserts a
  single batched EPSS lookup covers all findings' CVEs, and that `epss`/`kev`/`blastRadius`
  land on the right finding.
- A wiring-level test (new, `cmd`) that constructs the same stage graph `Main` does — but with
  fake `HttpFetcher`s instead of the real `JdkHttpFetcher`s — and runs it against the real
  `fixtures/sample-fpr/audit.fvdl` + `fixtures/sample-bdio/scan.json` fixtures (5 findings
  total: 2 SAST + 3 SCA). Asserts the run completes, produces 5 scored+advised findings, and
  the rendered Markdown contains the comment marker and expected CVE ids. No live network calls
  in the automated suite, consistent with every other module.
- A one-off manual run (not part of `./gradlew test`) against the same fixtures, executed once
  implementation lands, to confirm the shadow jar actually runs end-to-end from the command
  line as README describes.

## Open questions / explicit assumptions (not blocking, flagged for visibility)

- `--cache-dir` is a new flag `action.yml` doesn't set; its default (`.reachlayer/cache`
  relative to the working directory) is a reasonable CI default (ephemeral per-run in most CI
  setups) but not persisted across runs unless the caller mounts/caches that path themselves.
  Out of scope to wire up CI-level caching here.
- GitHub PR comment posting failure modes (missing env vars) degrade to a skipped-with-warning
  render rather than a CLI error, per PLAN.md principle 1. If the user wants a hard failure when
  `--post-pr-comment=true` is explicitly requested but env vars are missing, that's a one-line
  change to make later.
