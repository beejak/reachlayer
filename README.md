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

1. **Never fail or block the build.** Output is advisory only (PR comment today; SARIF/IDE
   later). Merge gating is explicitly out of scope.
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
output/github-pr  (single upserted, marker-tagged PR comment; never sets a failing check)
```

Everything is wired together by `core`'s `Orchestrator`, which is driven by the `cmd` picocli CLI
— runnable standalone or from the Docker-based GitHub Action (`action.yml`).

### Module map

| Module | Purpose |
|---|---|
| `core` | Canonical `Finding`/`Location`/`BlastRadius`/`FixSuggestion`/`Cvss` model, SPIs, `Orchestrator`, config loading. |
| `connectors` | `ScannerConnector` SPI plus `fortify` (FVDL/FPR) and `blackduck` (BDIO/JSON) parsers. |
| `reachability` | SootUp-based CHA call-graph construction, Spring/servlet entry-point discovery, `ReachabilityTagger`. |
| `enrich` | EPSS + CISA KEV disk-cached clients, blast-radius heuristics. |
| `scoring` | Deterministic blended risk score + per-factor explanation. |
| `advisor` | `LlmProvider` SPI: `noop` (templated) default, `anthropic` optional provider. |
| `output` | `OutputRenderer` SPI; `github-pr` single-comment upsert renderer. |
| `cmd` | picocli `Main` CLI entry point, produces the fat JAR used by the Docker action. |
| `fixtures` | Synthetic (not vendor) sample Fortify/Black Duck exports and a tiny vulnerable Spring Boot app used by tests. |

## Quickstart

Requires JDK 21.

```bash
./gradlew build          # compiles all modules and runs unit tests
./gradlew :cmd:shadowJar # builds the standalone fat JAR
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

### Running as a GitHub Action

```yaml
- uses: reachlayer/reachlayer@v0
  with:
    fortify-fvdl: audit.fvdl
    blackduck-bdio: scan.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action never fails the build — it only annotates the PR.

## Status

The full pipeline — connectors → reachability → enrich → scoring → advisor → output — is wired
end-to-end via `cmd`'s `Main` CLI and runnable today (see Quickstart above). Reachability uses
CHA/RTA-style call-graph approximation and component-level signatures; blast-radius and
entry-point discovery are intentionally simple, conservative heuristics that lean toward
`unknown` rather than claiming certainty. See `docs/reachability-caveats.md`.

## License

Apache-2.0, see [`LICENSE`](LICENSE).
