# Architecture

Reachlayer is a neutral risk-triage layer over unmodified Fortify (SAST) and Black Duck (SCA)
output. This document summarizes the system architecture defined in `PLAN.md` §2-§3; see that
file for the full rationale.

## Design principles

1. **Never fail or block the build.** All output is advisory (PR comment today; SARIF/IDE later).
   No merge gating.
2. **Layer, never replace.** Native Fortify FPR/FVDL XML and Black Duck BDIO/JSON exports are
   consumed as-is.
3. **Never suppress a finding.** Reachability (`reachable`/`unreachable`/`unknown`) is additive —
   used for ranking/grouping only, never for hiding a finding. See `reachability-caveats.md`.
4. **Every finding gets three things**: a blended, explainable risk score; a plain-language
   blast-radius explanation; a concrete fix suggestion.
5. **Pluggable.** Four SPIs make every stage swappable: `ScannerConnector`, `LlmProvider`,
   `OutputRenderer`, `SignatureSource` (all in `dev.reachlayer.core.spi`).

## Components and modules

| Module | Package | Responsibility |
|---|---|---|
| `core` | `dev.reachlayer.core` | `Finding`/`Location`/`BlastRadius`/`FixSuggestion`/`Cvss`/`RankedReport` model, the 4 SPIs, `reachlayer.yml` config loading, `Orchestrator`. |
| `connectors:api`, `:fortify`, `:blackduck` | `dev.reachlayer.connectors.*` | `ScannerConnector` implementations: streaming FVDL/FPR XML parser (Woodstox/StAX), Black Duck JSON parser (Jackson). |
| `reachability` | `dev.reachlayer.reach` | SootUp-based CHA call-graph construction from Spring/servlet entry points; `SignatureSource` for vulnerable-method/component lookups; `ReachabilityTagger`. |
| `enrich:epss`, `:kev`, `:blastradius` | `dev.reachlayer.enrich.*` | Disk-cached EPSS/KEV clients; heuristic blast-radius analyzer. |
| `scoring` | `dev.reachlayer.scoring` | Deterministic blended risk score + explanation (see `scoring.md`). |
| `advisor:api`, `:providers:noop`, `:providers:anthropic` | `dev.reachlayer.advisor.*` | `LlmProvider` SPI; templated fallback (default) and an Anthropic-backed provider. |
| `output:api`, `:github-pr`, `:sarif` | `dev.reachlayer.output.*` | `OutputRenderer` SPI; Markdown formatting; single-comment GitHub PR upsert; SARIF 2.1.0 report for GitHub code scanning (see `docs/sarif-output.md`). |
| `cmd` | `dev.reachlayer.cli` | picocli `Main`, wires everything via `Orchestrator`, produces the fat JAR the Docker action runs. |

## Data flow (MVP, synchronous in CI)

```
Fortify FVDL/FPR + Black Duck BDIO/JSON
        │  ScannerConnector.ingest(...)
        ▼
   canonical Finding[]
        │  ReachabilityStage: SootUp CHA call graph ∩ vulnerable-method signatures
        ▼
   Finding[] tagged reachable/unreachable/unknown
        │  EnrichmentStage: EPSS + KEV lookups, blast-radius heuristics
        ▼
   Finding[] + epss/kev/blastRadius
        │  ScoringStage: deterministic riskScore + riskExplanation
        ▼
   Finding[] + riskScore, sorted → RankedReport
        │  AdvisorStage: fix suggestion (LLM for top-N, templated otherwise)
        ▼
   Finding[] + fixSuggestion
        │  OutputRenderer(s): Markdown → single upserted PR comment
        ▼
   Pull request comment (never a failing check)
```

`core.pipeline.Orchestrator` wires this via constructor injection (`ScannerConnector` list,
`ReachabilityStage`, `EnrichmentStage`, `ScoringStage`, `AdvisorStage` functional interfaces,
`OutputRenderer` list, `ReachlayerConfig`). No DI framework is used — `cmd`'s `Main` composes the
concrete implementations from every module and binds them via method references.

Every stage failure (a bad connector, a broken renderer, an unreachable EPSS API) is caught and
logged inside the `Orchestrator`/individual clients — the pipeline degrades, it does not abort.
