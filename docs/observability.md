# Pipeline observability (metrics)

Every `Orchestrator.run(...)` call now records a `core.metrics.PipelineMetrics` snapshot, exposed
via `orchestrator.metrics()` after the run completes, and optionally written to disk as JSON via
`cmd`'s `--metrics-out` flag (or `action.yml`'s `metrics-out` input).

This is operational data for whoever runs Reachlayer in CI — it is not part of the PR comment or
the SARIF report, and nothing in `output/api`/`output/sarif` reads it. It exists so a CI operator
can answer "how long did each stage take" and "did anything degrade" without scraping logs.

## What's recorded

```json
{
  "startedAt": "2026-07-31T12:00:00Z",
  "completedAt": "2026-07-31T12:00:01.234Z",
  "totalDurationMs": 1234,
  "sourcesRequested": 2,
  "findingsIngested": 5,
  "stageDurationMs": { "reachability": 12, "enrichment": 340, "scoring": 1, "advisor": 210, "baseline": 0 },
  "stageErrors": {},
  "findingCountsBySeverity": { "Critical": 1, "High": 2, "Medium": 1, "4.0": 1 },
  "findingCountsBySource": { "fortify": 2, "blackduck": 3 },
  "findingCountsByReachability": { "unknown": 5 },
  "outputRenderersSucceeded": 2,
  "outputRenderersFailed": 0,
  "outputRendererErrors": {}
}
```

- **`stageDurationMs`** — wall-clock time per pipeline stage (reachability, enrichment, scoring,
  advisor, baseline). Every stage's `safeStage`/`timedStage` wrapping (PLAN.md principle 1) means a
  stage that fails still gets a duration recorded, and its failure is captured in `stageErrors`
  rather than aborting the run.
- **`findingCounts*`** — a breakdown of the final (post-baseline) finding list by severity, source,
  and reachability, useful for a CI dashboard without re-parsing the rendered report.
- **`outputRenderers*`** — how many configured renderers (console, PR comment, SARIF) succeeded vs.
  failed, and why, on this run.

## Usage

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --metrics-out reachlayer-metrics.json
```

Or via the Action:

```yaml
- uses: reachlayer/reachlayer@v0
  with:
    fortify-fvdl: audit.fvdl
    blackduck-bdio: scan.json
    metrics-out: reachlayer-metrics.json
```

Like every other optional output, this never fails the build: a `--metrics-out` write failure
(e.g. an unwritable directory) logs a warning and is otherwise silent, per PLAN.md principle 1.
