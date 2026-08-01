# Evaluation pipeline

A dedicated CI job (`.github/workflows/ci.yml`'s `evaluation` job) and a JUnit integration test
(`cmd`'s `EvaluationCorpusIT`) that answer a question no other test in this repo answers: **how
does the full pipeline actually behave at more-than-trivial scale, with real reachability
analysis enabled** — not the 5-finding golden-path fixture every other test uses, and not the
identity-passthrough (`--classes` omitted) every other CLI-wiring test uses.

## Why this exists

Every other test in this repo either uses the small, hand-written 5-finding fixture
(`fixtures/sample-fpr`/`fixtures/sample-bdio`) or passes an empty `--classes`, so
`ReachabilityTagger` never runs for real in the CLI-wiring tests — it only runs for real in
`reachability`'s own `ReachabilityTaggerFixtureIT`, in isolation from the rest of the pipeline.
Nothing exercised the *whole* pipeline — ingest, real reachability, enrichment, scoring, advisor,
baseline, all four output renderers — at a scale that would surface sorting, pagination, SARIF
rule-dedup, or metrics-collection bugs that only show up past a handful of findings.

## How it works

`fixtures:corpus-generator`'s `CorpusGenerator` produces a larger (~100+), deterministic
(seeded), varied synthetic Fortify FVDL + Black Duck JSON corpus. Three SAST "anchor" findings and
two SCA "anchor" components deliberately reference the real classes in
`fixtures:vulnerable-spring-app` (`ReachableVulnerableComponent`, `UnreachableVulnerableComponent`,
`VulnerableController`), so running the pipeline with `--classes` pointed at that module's real
compiled bytecode produces genuine `REACHABLE`/`UNREACHABLE` tags, not just `UNKNOWN`. The
remaining bulk findings (synthetic, plus a handful of real public CVEs like Log4Shell that aren't
actually part of this tiny fixture app) correctly tag `UNKNOWN` — a realistic "can't prove this
dependency's vulnerable path is reachable" outcome.

All corpus data is synthetic or references only public CVE identifiers — no real vendor scanner
output is ever bundled or fetched, per `PLAN.md` §9 risk #6.

```
fixtures:corpus-generator (CorpusGenerator.generate(seed, extraSast, extraSca))
        │
        ▼
audit.fvdl + scan.json  (~105 findings by default: 43 SAST + 62 SCA)
        │  full pipeline, --classes pointed at fixtures:vulnerable-spring-app's real bytecode
        ▼
RankedReport + report.md + report.sarif + baseline.json + metrics.json
```

## Two ways to run it

1. **`EvaluationCorpusIT`** (`cmd/src/test/java/dev/reachlayer/cli/EvaluationCorpusIT.java`) — runs
   in-process as part of every `./gradlew build`, asserting: total finding count matches the
   generated corpus exactly, at least one finding tagged `REACHABLE`, at least one
   `UNREACHABLE`, at least one `UNKNOWN`, every finding has a risk score, the rendered SARIF file
   is valid JSON with the right schema version, and `PipelineMetrics` records timing for every
   stage. This is the fast, always-run regression check.
2. **The `evaluation` CI job** (`.github/workflows/ci.yml`) — builds the real CLI jar, generates a
   fresh corpus via `fixtures:corpus-generator`'s standalone `Main` entry point, runs the actual
   `cmd-all.jar` against it (a true black-box smoke test, not in-process), asserts the same
   reachability-signal sanity check via a small script reading `metrics.json`, and uploads
   `report.md`/`report.sarif`/`baseline.json`/`metrics.json` as a downloadable CI artifact
   (`evaluation-corpus-results`, 14-day retention) so a human can inspect exactly what the pipeline
   produced for this run.

## What this does and doesn't replace

- It does **not** replace `sarif-dogfood` (which validates SARIF against GitHub's real code-scanning
  ingestion using the small, curated fixture) — the evaluation corpus's SARIF is deliberately
  **not** uploaded to code scanning, since ~100 synthetic findings would just add noise to the
  repo's real Security tab for no benefit. The two dogfooding mechanisms check different things:
  `sarif-dogfood` checks "does GitHub accept our SARIF," `evaluation` checks "does the pipeline
  behave sensibly at scale with real reachability signal."
- It does **not** replace real-world validation against actual Fortify/Black Duck output — see
  `docs/success-criteria.md`'s honest gap on that; synthetic data, however varied, is not the same
  as messy real vendor export quirks.

## Running it locally

```bash
./gradlew :cmd:shadowJar :fixtures:vulnerable-spring-app:compileJava
./gradlew :fixtures:corpus-generator:run --args="/tmp/eval-corpus 42 40 60"
java -jar cmd/build/libs/cmd-all.jar \
  --fortify /tmp/eval-corpus/audit.fvdl \
  --blackduck /tmp/eval-corpus/scan.json \
  --repo . \
  --classes fixtures/vulnerable-spring-app/build/classes/java/main \
  --out /tmp/eval-corpus/report.md \
  --sarif-out /tmp/eval-corpus/report.sarif \
  --metrics-out /tmp/eval-corpus/metrics.json
cat /tmp/eval-corpus/metrics.json
```

The `Main.java` args are `<outputDir> [seed=42] [extraSastCount=40] [extraScaCount=60]` — change
the seed or counts to generate a different (still deterministic per-seed) corpus.
