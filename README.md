# Reachlayer

**A neutral, non-blocking risk-triage layer that sits on top of Fortify (SAST) and Black Duck
(SCA) and tells developers, in their pull request, which findings actually matter.**

Enterprise AppSec teams running Fortify and Black Duck are drowning: 40-80% of SAST findings are
non-exploitable, engineers burn up to 80% of their week on triage, and backlogs of
15,000-30,000 findings make everything look equally (un)urgent. Every commercial ASPM that
promises to fix this eventually pressures you to rip out Fortify and Black Duck and adopt its own
scanners.

Reachlayer is the missing open-source alternative: it ingests **unmodified** Fortify and Black
Duck output, adds static reachability analysis, EPSS/KEV exploitability signals, and
plain-language blast-radius context, then posts one prioritized, developer-readable comment on
the pull request — as advisory context, **never as a blocking gate**. It answers the only
question a developer actually asks:

> Of these 847 SAST + 312 SCA findings, which handful can actually hurt us, and how do I fix them?

## Non-negotiable design principles

1. **Never fail or block the build.** Output is advisory only (PR comment, SARIF, or a Markdown
   file). Merge gating is explicitly out of scope.
2. **Layer, never replace.** Consumes native Fortify FPR/FVDL XML and Black Duck BDIO/JSON
   exports as-is. Fortify and Black Duck stay exactly as they are.
3. **Never suppress a finding.** Static reachability is unsound (false negatives are possible).
   Reachability (`reachable` / `unreachable` / `unknown`) is additive — used for ranking and
   grouping, never for hiding a finding.
4. **Every finding gets three things:** a blended, explainable risk score; a plain-language
   blast-radius explanation; and a concrete fix suggestion (LLM-generated when a provider is
   configured, templated otherwise).
5. **Open source & pluggable.** Apache-2.0. `ScannerConnector`, `LlmProvider`, `OutputRenderer`
   and `SignatureSource` are SPIs so the community can add scanners, providers, and outputs
   without touching the core.

See [`PLAN.md`](PLAN.md) for the full architecture and roadmap this repository implements.

## Getting started — the short version

If you just want to see it run, with no prior knowledge of this project required:

```bash
# 1. You need a JDK 21 installed. Check with:
java -version   # must print 21.x — if not, install Temurin 21 from https://adoptium.net

# 2. Clone this repo and build it (this compiles everything and runs the test suite):
git clone https://github.com/reachlayer/reachlayer.git
cd reachlayer
./gradlew build

# 3. Run it against the sample scanner exports already checked into this repo:
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --out report.md

# 4. Read the result:
cat report.md
```

That's it — no scanner license, no GitHub token, no API keys needed for this. Step 3 is the CLI
running fully standalone. If any output is unclear, jump to the [CLI flag reference](#cli-flag-reference)
below, which lists every flag in plain language.

**Prefer Docker?** No JDK install needed at all:

```bash
docker build -t reachlayer .
docker run --rm -v "$PWD:/workspace" -w /workspace reachlayer \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo /workspace \
  --out /workspace/report.md
cat report.md
```

This is the exact same image `action.yml` runs as a GitHub Action — see
[Running as a GitHub Action](#running-as-a-github-action) below for the CI-native version of this.

## Architecture summary

```
Fortify FPR/FVDL + Black Duck BDIO/JSON
        │  connectors/{fortify,blackduck}  →  canonical Finding[]
        ▼
reachability/  (SootUp CHA call graph from Spring/servlet entry points
                 ∩ vulnerable-method/component signatures)
        ▼
enrich/  (EPSS + CISA KEV disk-cached clients, blast-radius heuristics)
        ▼
scoring/  (deterministic, explainable riskScore + riskExplanation, reachlayer.yml-tunable)
        ▼
advisor/  (LlmProvider SPI: templated "noop" fallback by default, Anthropic provider optional)
        ▼
core.baseline (optional)  (tag new-vs-pre-existing findings against a prior baseline run)
        ▼
output/  (Markdown → single upserted PR comment; SARIF 2.1.0 for GitHub code scanning; metrics JSON)
```

Everything is wired together by `core`'s `Orchestrator`, which is driven by the `cmd` picocli CLI
— runnable standalone, via Docker, or from the Docker-based GitHub Action (`action.yml`).

### Module map

| Module | Purpose |
|---|---|
| `core` | Canonical `Finding`/`Location`/`BlastRadius`/`FixSuggestion`/`Cvss` model, the 4 SPIs, `Orchestrator`, `reachlayer.yml` config loading, baseline/diff mode (`core.baseline`), pipeline observability (`core.metrics`). |
| `connectors` | `ScannerConnector` SPI plus `fortify` (FVDL/FPR) and `blackduck` (BDIO/JSON) parsers. |
| `reachability` | SootUp-based CHA call-graph construction, Spring/servlet entry-point discovery, `ReachabilityTagger`. |
| `enrich` | EPSS + CISA KEV disk-cached clients, blast-radius heuristics. |
| `scoring` | Deterministic blended risk score + per-factor explanation. |
| `advisor` | `LlmProvider` SPI: `noop` (templated) default, `anthropic` optional provider. |
| `output` | `OutputRenderer` SPI; `api` (Markdown formatting), `github-pr` (single-comment upsert), `sarif` (SARIF 2.1.0 for GitHub code scanning). |
| `cmd` | picocli `Main` CLI entry point, produces the fat JAR used by the Docker action. |
| `fixtures` | Synthetic (never real vendor) sample Fortify/Black Duck exports, a tiny vulnerable Spring Boot app used by reachability tests, and a larger synthetic-corpus generator for the evaluation pipeline. |

## Quickstart (for contributors)

Requires JDK 21.

```bash
./gradlew build          # compiles all modules and runs the full test suite
./gradlew :cmd:shadowJar # builds the standalone fat JAR at cmd/build/libs/cmd-all.jar
```

Run the CLI directly against local scanner exports:

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --config reachlayer.yml \
  --out report.md
```

With `GITHUB_TOKEN`, `GITHUB_REPOSITORY` and `GITHUB_PR_NUMBER` set, the CLI will also upsert the
rendered report as a single PR comment via `output/github-pr`.

## CLI flag reference

Every flag the CLI accepts, in plain language. All flags are optional except where noted; a blank
or omitted value means "skip this feature" — nothing here is required to get a basic run working.

| Flag | Default | What it does |
|---|---|---|
| `--fortify <path>` | *(none)* | Path to a Fortify `audit.fvdl` or `.fpr` export to ingest. Omit if you have no Fortify data. |
| `--blackduck <path>` | *(none)* | Path to a Black Duck JSON/BDIO export to ingest. Omit if you have no Black Duck data. |
| `--repo <path>` | `.` | Path to the checked-out repository — used to pull code snippets for fix suggestions. |
| `--classes <path>` | *(none)* | Path to your app's **compiled** `.class` files. Without this, every finding's reachability is tagged `unknown` (safe, honest default) instead of `reachable`/`unreachable`. |
| `--config <path>` | *(none)* | Path to a `reachlayer.yml` file to override default scoring weights, advisor settings, etc. See [`reachlayer.yml`](reachlayer.yml) for an example. |
| `--out <path>` | *(none)* | Also write the rendered Markdown report to this file (in addition to printing it to the console). |
| `--sarif-out <path>` | *(none)* | Also write a [SARIF 2.1.0](docs/sarif-output.md) report to this file, for upload to GitHub code scanning via a separate `github/codeql-action/upload-sarif` step. |
| `--baseline-in <path>` | *(none)* | Path to a baseline JSON file (finding IDs from a prior run, e.g. a scheduled scan of your base branch). When set, the report highlights only *new* findings. See [`docs/baseline-mode.md`](docs/baseline-mode.md). |
| `--baseline-out <path>` | *(none)* | Write this run's finding IDs to this path, to be used as a future run's `--baseline-in`. |
| `--metrics-out <path>` | *(none)* | Write pipeline observability data (per-stage timing, finding counts, renderer outcomes) as JSON to this path. See [`docs/observability.md`](docs/observability.md). |
| `--cache-dir <path>` | `.reachlayer-cache` | Where EPSS/KEV data is cached on disk (refreshed daily). |
| `--post-pr-comment <true\|false>` | `true` | Whether to upsert a PR comment via the GitHub REST API. Requires `GITHUB_TOKEN`/`GITHUB_REPOSITORY`/`GITHUB_PR_NUMBER` — if any are missing, this is silently skipped (logged, not an error). |

Run `java -jar cmd/build/libs/cmd-all.jar --help` at any time to see this list from the CLI itself.

### Running as a GitHub Action

```yaml
- uses: reachlayer/reachlayer@v0
  with:
    fortify-fvdl: audit.fvdl        # optional — omit if you have no Fortify data
    blackduck-bdio: scan.json       # optional — omit if you have no Black Duck data
    classes-dir: target/classes     # optional — enables real reachable/unreachable tagging
    sarif-out: reachlayer.sarif     # optional — see docs/sarif-output.md
    baseline-in: reachlayer-baseline.json   # optional — see docs/baseline-mode.md
    baseline-out: reachlayer-baseline.json  # optional
    metrics-out: reachlayer-metrics.json    # optional — see docs/observability.md
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action never fails the build — it only annotates the PR. Every input mirrors a CLI flag above
one-for-one (e.g. `fortify-fvdl` → `--fortify`); see [`action.yml`](action.yml) for the complete
list of inputs/outputs.

## Documentation map

| Doc | What it covers |
|---|---|
| [`PLAN.md`](PLAN.md) | Full vision, design principles, phased roadmap, tech stack, scoring formula. |
| [`docs/architecture.md`](docs/architecture.md) | Module/package table, data-flow diagram, testing strategy. |
| [`docs/scoring.md`](docs/scoring.md) | The exact risk-scoring formula and tunable weights. |
| [`docs/connectors.md`](docs/connectors.md) | How to write a new `ScannerConnector` for another scanner. |
| [`docs/reachability-caveats.md`](docs/reachability-caveats.md) | Honest soundness/false-negative disclosure for the reachability engine. |
| [`docs/sarif-output.md`](docs/sarif-output.md) | The SARIF renderer, its GitHub code-scanning mapping, and the `upload-sarif` workflow step. |
| [`docs/baseline-mode.md`](docs/baseline-mode.md) | Baseline/diff mode: surfacing only new findings vs. a prior run. |
| [`docs/observability.md`](docs/observability.md) | Pipeline metrics: per-stage timing, finding counts, renderer outcomes. |
| [`docs/evaluation-pipeline.md`](docs/evaluation-pipeline.md) | The larger synthetic-corpus evaluation pipeline and its CI job. |
| [`docs/success-criteria.md`](docs/success-criteria.md) | Concrete, falsifiable success/failure criteria for the repo and its tests, including honest gaps. |
| [`docs/architecture-optimization.md`](docs/architecture-optimization.md) | Network-design and optimization review. |
| [`docs/lessons-learned.md`](docs/lessons-learned.md) | Running log of concrete findings from building this project. |

## Status

The full pipeline — connectors → reachability → enrich → scoring → advisor → baseline → output —
is wired end-to-end via `cmd`'s `Main` CLI and runnable today (see Getting Started above).
`PLAN.md` Phase 0 (MVP) and the first two Phase 1 items (SARIF output, baseline/diff mode) are
implemented; pipeline observability metrics and a dedicated evaluation pipeline (see
[`docs/evaluation-pipeline.md`](docs/evaluation-pipeline.md)) have also landed. Reachability uses
CHA/RTA-style call-graph approximation and component-level signatures; blast-radius and
entry-point discovery are intentionally simple, conservative heuristics that lean toward
`unknown` rather than claiming certainty. See `docs/reachability-caveats.md`.

## License

Apache-2.0, see [`LICENSE`](LICENSE).
