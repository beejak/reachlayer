# Success and failure criteria

Concrete, falsifiable statements of what "this repo works" and "this repo is broken" mean —
written so a reviewer can check each claim against an actual test or CI run, not just trust a
description. See `docs/lessons-learned.md` for concrete gaps this bar has already surfaced.

## Success

1. **`./gradlew build` passes, every module, no flakiness.** All connector, pipeline, renderer, and
   CLI-wiring tests green. Verified continuously by `.github/workflows/ci.yml`'s `build` job.
2. **The build never fails because of Reachlayer itself (PLAN.md principle 1).** Concretely: a
   connector that throws, a pipeline stage that throws, an output renderer that throws, or a
   missing/corrupt optional-feature input (baseline file, SARIF path, metrics path) must all
   degrade to a logged warning and exit code `0` — never an uncaught exception, never a non-zero
   exit for any reason except malformed CLI arguments themselves. Verified by:
   `OrchestratorTest#connectorFailureIsSkippedNotThrown`,
   `OrchestratorTest#outputFailureDoesNotPropagate`,
   `OrchestratorTest#metricsRecordsStageErrorWhenAStageThrows`,
   `SarifOutputRendererTest#wrapsIoFailureAsOutputException`,
   `BaselineStoreTest`'s three never-throws tests, `MetricsWriterTest#isNoOpAndNeverThrowsWhenPathIsNull`.
3. **Scanner ingestion is correct across messy input, not just the golden-path fixture.** Missing
   CWE/location/severity, empty finding lists, malformed XML/JSON, an XXE attempt, duplicate CVEs
   across components, and shared-ClassID Fortify instances all produce the expected `Finding`s or
   the expected `ConnectorException` — never a crash, never silently wrong data. Verified by the 24
   connector edge-case tests added across `FvdlParserTest`, `FortifyConnectorTest`, and
   `BlackDuckConnectorTest` (previously only happy-path coverage existed — see
   `docs/lessons-learned.md`'s entry on this).
4. **Generated SARIF is accepted by GitHub's actual code-scanning ingestion, not just locally
   schema-plausible.** Verified two ways: locally (`SarifReportBuilderTest`,
   `SarifOutputRendererTest` — structure, null-omission, rule dedup), and externally by
   `.github/workflows/ci.yml`'s `sarif-dogfood` job, which builds the real CLI, runs it against the
   fixtures, and uploads the result through `github/codeql-action/upload-sarif@v3` against this
   very repository — a rejected/malformed SARIF file fails that CI step. This is the ground-truth
   check no amount of local schema reading can substitute for.
5. **Baseline/diff mode correctly identifies new vs. pre-existing findings across independent
   runs**, not just in a single in-memory pass. Verified by
   `MainWiringIT#baselineRoundTripTagsAllFindingsAsPreExistingWhenNothingChanged`, which runs the
   real CLI twice against the real fixtures (write, then read) and asserts every finding comes back
   correctly tagged.
6. **No finding is ever silently dropped from the rendered output.** Reachability tagging is
   additive-only (never hides a finding); baseline/diff mode changes which section a finding is
   *shown in*, never whether it's shown at all — enforced by
   `MarkdownReportFormatterTest`'s baseline-mode tests, which assert every finding (new or
   pre-existing) is present somewhere in the rendered Markdown.
7. **Manual end-to-end runs against the real fixtures produce correct output**, confirmed by
   direct inspection each time a feature was added this session (SARIF: rule dedup and synthetic
   locations checked by hand; baseline: round-trip output inspected; metrics: JSON output inspected
   and shown to reflect a real network-degradation event caught during this exact process).
8. **The full pipeline, at more-than-trivial scale, produces genuine reachability signal — not
   just `unknown`.** Verified by `cmd`'s `EvaluationCorpusIT` and the CI `evaluation` job (see
   `docs/evaluation-pipeline.md`): a ~105-finding synthetic corpus run through the real CLI with
   `--classes` pointed at `fixtures:vulnerable-spring-app`'s real compiled bytecode produced exactly
   the expected distribution — 3 `REACHABLE`, 2 `UNREACHABLE`, 100 `UNKNOWN` — matching the 3
   SAST + 2 SCA anchor findings that reference real classes in that fixture app. This directly
   narrows the "reachability engine not independently re-verified" gap noted below: the engine
   itself wasn't modified, but its behavior end-to-end through the full pipeline is now genuinely
   exercised at scale, not just via the pre-existing isolated `ReachabilityTaggerFixtureIT`.
9. **A real correctness bug was found and fixed, not just latency nits.** An architecture/network
   review (`docs/architecture-optimization.md`) found that `GitHubRestApiClient.listIssueComments`
   never paginated — on a PR with more than GitHub's default 30-comment page size, Reachlayer's
   marker comment could be invisible, causing a duplicate comment instead of an upsert (silently
   defeating this project's own "single upserted comment" design goal). Fixed and verified against
   a real local HTTP server (`GitHubRestApiClientTest`, using JDK's built-in `HttpServer` — this
   class previously had no dedicated test at all). A related inefficiency (`EnrichmentPipeline`
   re-reading/re-parsing the on-disk KEV cache file once per finding instead of once per run) was
   fixed alongside it.

## Failure

Any of the following is a regression, full stop:

- A test suite fails in CI.
- The CLI process exits non-zero for any reason other than a malformed CLI invocation itself
  (picocli's own usage-error exit is not a Reachlayer failure).
- The `sarif-dogfood` CI job's `upload-sarif` step fails — meaning GitHub itself rejected the
  generated SARIF as invalid.
- A finding present after ingestion is absent from every rendered output (Markdown, SARIF) with no
  code path that can explain why (this would violate PLAN.md principle 3).
- A live EPSS/KEV network failure crashes the pipeline instead of degrading to cache/empty-result
  fallback (see the honest gap below — this is *tested* only via fake fetchers, never against a
  live failure, though this exact fallback was observed for real in this sandbox, see
  `docs/lessons-learned.md`).
- The `evaluation` CI job's reachability sanity check fails (i.e. the ~105-finding synthetic
  corpus stops producing at least one `REACHABLE` and one `UNREACHABLE` finding) — this would mean
  either the corpus generator's anchors or the reachability engine's behavior regressed.

## Known gaps (honest, not swept under the rug)

- **Connectors are tested only against synthetic fixtures**, never real Fortify/Black Duck export
  quirks — a deliberate project constraint (`PLAN.md` §9 risk #6: no real vendor data may be
  bundled or fetched, for licensing and confidentiality reasons), not an oversight. Real-world
  fidelity beyond what the synthetic fixtures + new edge-case tests cover remains unverified.
- **EPSS/KEV live HTTP paths are untested against the real APIs** in automated tests (only fake
  `HttpFetcher`s are used, per repo-wide test convention) — but the graceful-degradation path
  *was* exercised for real in this session, when this sandbox's proxy blocked the live calls and
  the pipeline correctly fell back and still produced a complete report.
- **The reachability (SootUp call-graph) engine's internals were not modified** during this round
  of work — its correctness predates this session. Its end-to-end behavior through the full
  pipeline is now exercised at scale by the evaluation pipeline (item 8 above), but that is a
  behavioral/integration check, not a re-verification of `CallGraphBuilder`'s SootUp usage itself.
- **No dedicated fuzz/property test asserts "finding count is conserved end-to-end"** beyond the
  additive-by-design architecture and the targeted tests above — a reasonable future addition for
  even higher confidence, not currently present.

## Re-validating this bar

```bash
./gradlew build
java -jar cmd/build/libs/cmd-all.jar --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json --repo . \
  --sarif-out /tmp/r.sarif --baseline-out /tmp/r-baseline.json --metrics-out /tmp/r-metrics.json
```

Then watch `.github/workflows/ci.yml`'s `build`, `sarif-dogfood`, and `evaluation` jobs all pass on
the next push/PR.
