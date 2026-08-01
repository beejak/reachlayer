# Reachlayer — Implementation Plan

> A neutral reachability + risk-context layer that sits *on top of* Fortify (SAST) and Black Duck (SCA) and tells developers, in their PR, which of the thousands of findings actually matter — without replacing their scanners and without blocking their build.

---

## 1. Vision & Name

**Project name:** **Reachlayer** (working name; alternatives: *Overwatch*, *Triagelayer*, *Signalfire*, *Reachr*). "Reachlayer" captures the two core ideas: **reachability** analysis and being a **layer** on top of existing tools rather than a replacement.

**Vision (pitch):** Enterprise AppSec teams running Fortify and Black Duck are drowning — 40-80% of SAST findings are non-exploitable, engineers burn up to 80% of their week on triage, and backlogs of 15,000-30,000 findings make everything look equally (un)urgent. **Reachlayer is the missing open-source alternative: a neutral enrichment layer that ingests *unmodified* Fortify and Black Duck output, adds static reachability analysis, EPSS/KEV exploitability signals, and plain-language blast-radius context, then posts a prioritized, developer-readable summary directly into the pull request — as advisory context, never as a blocking gate.** It answers the only question a developer actually asks: "Of these 847 SAST + 312 SCA findings, which handful can actually hurt us, and how do I fix them?"

**Positioning (the gap being filled) — corrected 2026-08-01 against actual competitive research** (see `docs/competitive-landscape-oss.md` and `docs/competitive-landscape-commercial-technical.md`; this paragraph previously overstated the "rip out your scanners" framing, which a competitive review found true for only 1 of 6 commercial ASPMs checked): DefectDojo ingests both scanners but is a batch dashboard with no reachability. OWASP dep-scan/atom does reachability *and* goes further — its `atom`/Joern-CPG engine does interprocedural taint/data-flow slicing, a strictly stronger claim than Reachlayer's current CHA-only call-graph reachability — but it doesn't ingest Fortify/Black Duck output specifically. Apiiro, OX Security, Cycode, and Legit Security all already ingest Fortify and/or Black Duck as a layer, contradicting the "every commercial ASPM makes you replace your scanners" framing this paragraph used to have; only Aikido genuinely fits that description among the six vendors checked. Reachlayer's real, defensible differentiator is narrower than originally stated: **open-source, self-hostable, PR-native single-comment output, and a transparent/inspectable scoring formula**, against a commercial landscape that is closed-source, dashboard-first, and (with one exception) enterprise-sales-gated — not the ingest-vs-replace axis alone, which several commercial products already share with Reachlayer. The reachability-layered-on-unmodified-Fortify/Black-Duck-output combination specifically does still appear to be uncontested among the projects checked.

**Further correction, same date, from OSS-side research** (`docs/competitive-landscape-oss.md`): the vendors themselves are the closest prior art on the reachability *technique*, not just adjacent tooling. Black Duck Detect already ships a native, Java-only, call-graph-based reachability tag (`--detect.impact.analysis.enabled`) that may already be present in a customer's "unmodified" Black Duck export (see risk #11 below and `docs/connectors.md`). Fortify's own `fortify/skills` repo ships an interactive AI-agent exploitability-triage skill on the same premise. OWASP dep-scan/atom's usage-slicing and Semgrep Supply Chain's dataflow/taint reachability are both more technically precise than Reachlayer's CHA-only approach, and Semgrep has publicly critiqued CHA-only ("transitive") reachability as prone to false positives on "reachable" (see `docs/reachability-caveats.md`). **The honest pitch is not "reachability for Fortify/Black Duck output, which nobody else does" — it's "cross-scanner (SAST+SCA) correlation, vendor-neutral OSS, and non-blocking PR-native delivery," none of which any of the above provide.** Do not lead with the reachability-novelty framing to a technically literate audience.

---

## 2. Core Design Principles (non-negotiable, baked into every phase)

1. **Never fail or block the build.** Output is advisory: PR comments, SARIF annotations, IDE hints. Merge gating is explicitly out of scope — this is the key differentiator from gate-focused ASPM tools.
2. **Layer, never replace.** Consume native export formats (Fortify FPR/XML, Black Duck BDIO/REST JSON) as-is. The customer keeps Fortify and Black Duck exactly as they are.
3. **Never suppress a finding.** Static reachability is *unsound* (false negatives possible). Reachability is an **additive attribute** (`Reachable` / `Unreachable` / `Unknown`), used for *ranking and grouping*, never for hiding findings.
4. **Every finding gets three things:** a blended **risk score** (CVSS + EPSS/KEV + reachability), a plain-language **blast-radius explanation** (internet-facing? touches auth/PII/secrets? what's downstream?), and a concrete **fix suggestion** (version bump / code pattern / config change), ideally LLM-generated from retrieved context, not templated.
5. **Open source & community-first.** Apache-2.0 license. Plugin architecture so Snyk, Semgrep, Checkmarx, etc. can be added as scanner connectors later without touching the core.
6. **Event-driven consumer, not a poller-per-finding.** Cache EPSS (daily) and KEV (hourly/daily diff) locally. Consume Black Duck Rapid Scan synchronously; consume Fortify SSC via webhook-with-polling-fallback. "Real-time" = "as soon as the scan/API reports completion."

---

## 3. System Architecture

### 3.1 Components

| Component | Responsibility |
|---|---|
| **Ingestion adapters** (`connectors/`) | Pluggable per-scanner parsers. MVP: `fortify-fpr` (parse FPR/audit.fvdl XML + SSC REST) and `blackduck` (BDIO + REST JSON). Normalize to a common **Finding** model. |
| **Normalizer / dedup** | Map heterogeneous scanner output into a canonical `Finding` schema; correlate/dedup across scanners (same CVE flagged by both SAST config check + SCA). |
| **Reachability engine** (`reachability/`) | Build an app-side call graph from Spring/servlet entry points using **SootUp**; intersect against vulnerable-method signatures; tag each finding `Reachable` / `Unreachable` / `Unknown`. |
| **Exploitability enricher** (`enrich/epss-kev`) | Locally-cached EPSS scores + CISA KEV membership per CVE. |
| **Blast-radius analyzer** (`enrich/blastradius`) | Heuristics over the call graph + code metadata: is the sink internet-facing (reachable from an HTTP handler)? does the path touch auth / PII / secrets / DB / crypto? what's downstream? |
| **Risk scorer** (`scoring/`) | Deterministic blended score: `f(CVSS, EPSS, KEV, reachability, blast-radius)`. Explainable and configurable weights. |
| **Fix advisor** (`advisor/`) | LLM-generated remediation using retrieved context (advisory text + offending code snippet + dependency graph). Pluggable LLM provider; degrades to templated guidance if no key configured. |
| **Output renderers** (`output/`) | MVP: **PR comment** (GitHub). Later: SARIF, IDE, dashboard. |
| **Orchestrator / CLI** (`cmd/`) | Ties it together; runs as a GitHub Action and as a standalone CLI. |
| **Event intake** (Phase 1+) | Webhook receiver (Fortify SSC scan-complete, Black Duck) + polling fallback. In MVP this is just synchronous CI-step logic. |

### 3.2 Data flow (MVP, synchronous in CI)

```
                         ┌──────────────────────────────────────────────┐
                         │                  Pull Request                 │
                         └───────────────────────┬──────────────────────┘
                                                 │ triggers GitHub Action
                                                 ▼
   ┌───────────────┐   ┌───────────────┐   ┌─────────────────────────────┐
   │ Fortify SAST  │   │  Black Duck   │   │  Reachlayer GitHub Action   │
   │ (ScanCentral/ │   │  (Rapid Scan/ │   │  (orchestrator)             │
   │  SSC)         │   │   Detect)     │   │                             │
   └──────┬────────┘   └──────┬────────┘   └──────────────┬──────────────┘
          │ .fpr / SSC REST   │ BDIO / REST                │
          ▼                   ▼                            ▼
   ┌──────────────────────────────────────┐   ┌────────────────────────────┐
   │  Ingestion adapters  →  Normalizer     │   │  Local caches               │
   │  → canonical Finding[]  (+dedup)       │   │  • EPSS (daily snapshot)    │
   └──────────────────┬─────────────────────┘   │  • CISA KEV (daily diff)    │
                      │                          │  • OSV/GHSA vuln-method sigs│
                      ▼                          └──────────────┬─────────────┘
   ┌──────────────────────────────────────┐                    │
   │  Reachability engine (SootUp)         │◄───────────────────┘
   │  app call graph from entry points     │
   │  ∩ vulnerable-method signatures       │
   │  ⇒ Reachable / Unreachable / Unknown  │
   └──────────────────┬────────────────────┘
                      ▼
   ┌──────────────────────────────────────┐
   │  Enrich: EPSS + KEV + blast-radius     │
   └──────────────────┬─────────────────────┘
                      ▼
   ┌──────────────────────────────────────┐
   │  Risk scorer (CVSS+EPSS+KEV+reach+     │
   │  blast) ⇒ ranked, grouped findings     │
   └──────────────────┬─────────────────────┘
                      ▼
   ┌──────────────────────────────────────┐
   │  Fix advisor (LLM + retrieved context) │
   └──────────────────┬─────────────────────┘
                      ▼
   ┌──────────────────────────────────────┐
   │  Output: PR comment (upsert)           │
   │  "Top 5 that matter, why, how to fix"  │
   │  + collapsible full ranked list        │
   │  NEVER sets a failing check status     │
   └────────────────────────────────────────┘
```

### 3.3 Canonical `Finding` model (the contract every connector emits)

```
Finding {
  id                 // stable hash: source + rule + location + component
  source             // "fortify" | "blackduck"
  kind               // "sast" | "sca"
  cve[]              // associated CVE ids (may be empty for SAST)
  cwe[]              // associated CWE ids
  component          // package@version (SCA) or null
  location {         // file, line, function/method signature
    file, startLine, endLine, methodSignature
  }
  severity           // scanner-reported (kept as-is, never overridden)
  cvss { score, vector }
  rawScannerFields   // opaque bag preserved for traceability
  // --- fields Reachlayer ADDS ---
  reachability       // "reachable" | "unreachable" | "unknown"
  reachEvidence      // call-path summary or "no path found" or "not analyzed"
  epss               // { score, percentile } | null
  kev                // bool
  blastRadius {      // internetFacing, touchesAuth, touchesPII, touchesSecrets, downstream[]
  }
  riskScore          // 0-100 blended, explainable
  riskExplanation    // component contributions
  fixSuggestion {    // type: version-bump|code-fix|config; text; confidence; source (llm|template)
  }
}
```

---

## 4. MVP Scope (Phase 0) — deliberately narrow

**In scope for the first shippable version:**

- **Language/framework:** **Java + Spring Boot only** (most mature for reachability; SootUp/WALA/Steady/Endor/dep-scan precedent). Entry points: `main`, Spring MVC annotations (`@RequestMapping`, `@GetMapping`, `@PostMapping`, etc.), servlet `doGet`/`doPost`.
- **CI target:** **GitHub Actions** only.
- **Ingested scanners:** **Black Duck** (SCA) and **Fortify** (SAST) only — via native offline exports first (Fortify FPR/FVDL XML, Black Duck BDIO/JSON), with SSC/REST API paths as a secondary code path.
- **Reachability:** static **call-graph** reachability (CHA/RTA approximation via SootUp) — "is the vulnerable method reachable from an app entry point." Deep taint/data-flow reachability is deferred.
- **Vulnerable-method signatures:** sourced from **OSV/GHSA** advisory data where affected function names exist; where they don't, fall back to component-level reachability ("is any method of this vulnerable dependency reachable"). Optionally consume OWASP **dep-scan / atom** reachables-slice output as an alternative signature source.
- **Exploitability:** locally-cached **EPSS** + **CISA KEV**.
- **Blast-radius:** heuristic tags (internet-facing via reachable-from-HTTP-handler; touches auth/PII/secrets/DB via package/annotation/name heuristics).
- **Fix advisor:** LLM-generated (pluggable provider, config via env/secret) with a deterministic **templated fallback** so the tool is fully functional with no LLM key.
- **Output:** **single upserted PR comment** — a "Top N that matter" section with risk score, one-line why, and fix, plus a collapsible full ranked table. **No check-run failure, ever.**
- **Packaging:** a **GitHub Action** wrapping a **CLI**; CLI also runnable locally/standalone.

**Explicitly NOT in the MVP:** multi-language reachability; taint/data-flow reachability; IDE plugin; auto-remediation PRs; self-hosted dashboard/web UI; webhook event service; additional scanner connectors (Snyk/Semgrep/Checkmarx); merge gating of any kind.

**MVP definition of done:** On a sample vulnerable Spring Boot repo with real Fortify FPR + Black Duck BDIO artifacts, opening a PR produces a PR comment that (1) ranks findings by blended risk, (2) correctly tags at least the obvious reachable/unreachable cases, (3) shows EPSS/KEV, (4) gives a fix per top finding, and (5) never fails the build.

---

## 5. Phased Roadmap

### Phase 0 — MVP (see §4)
Java/Spring, GitHub Actions, Fortify + Black Duck (offline exports), call-graph reachability via SootUp, EPSS/KEV, heuristic blast-radius, LLM-or-template fix advisor, single PR comment, Apache-2.0, plugin-shaped connector interface even though only two connectors exist.

### Phase 1 — Harden & connect live
- **Live API ingestion:** Fortify SSC REST (poll-until-complete with configurable interval) + Black Duck REST/Rapid Scan synchronous path.
- **Event-driven intake service:** webhook receiver (Fortify SSC scan-complete / JMS, Black Duck) with **polling fallback**, so Reachlayer can run as a small always-on service, not only inside a CI step.
- **SARIF output renderer** (GitHub code-scanning annotations, still non-blocking) — implemented:
  `output/sarif`'s `SarifOutputRenderer`, wired via `cmd`'s `--sarif-out` flag / `action.yml`'s
  `sarif-out` input. See `docs/sarif-output.md`.
- **Baseline/diff mode** (only surface *new* findings introduced by the PR vs. the base branch, to
  fight backlog noise) — implemented: `core.baseline`'s `BaselineStore`/`BaselineDiffer` plus
  `Finding#isNew()`, wired via `cmd`'s `--baseline-in`/`--baseline-out` flags and `action.yml`'s
  matching inputs. See `docs/baseline-mode.md`.
- **Incremental call-graph construction** (IncCHA-style graph patching) for CI speed on large codebases.
- Config file (`reachlayer.yml`): scoring weights, entry-point overrides, LLM provider, suppression-of-*display* rules (never suppression of data).

### Phase 2 — Broaden reach
- **Additional languages:** JS/TS then Python reachability (moderate maturity; document soundness caveats loudly).
- **Deeper reachability:** optional taint/data-flow mode (integrate/borrow from CodeQL/Semgrep/dep-scan/atom) for higher-confidence "attacker-controlled input reaches sink."
- **More scanner connectors:** Snyk, Semgrep/OpenGrep, Checkmarx — proving the plugin architecture.
- **More CI targets:** GitLab CI, Azure DevOps, Jenkins, Bitbucket.

### Phase 3 — Developer surfaces & self-hosting
- **IDE plugin** (VS Code / IntelliJ) showing per-finding risk + fix inline.
- **Self-hosted dashboard** (trends, backlog burn-down, SLA tracking) — a complement to, not replacement of, DefectDojo; consider a DefectDojo integration/export instead of reinventing.
- **Auto-remediation PRs** for the high-confidence, low-risk-of-breakage cases (dependency version bumps first).

### Deferred / maybe-never (explicitly)
Merge-blocking gates (against the core principle); becoming a scanner itself (against the core principle); C/C++ reachability (weak for this use case).

---

## 6. Tech Stack (MVP)

| Concern | Choice | Rationale |
|---|---|---|
| **Core tool language/runtime** | **Java 21 (JVM)** | The reachability engine (SootUp) is a JVM library operating on JVM bytecode; keeping the whole tool on the JVM avoids a cross-process/IPC boundary for the most complex component. Also the analysis target is Java. |
| **Call-graph library** | **SootUp** (primary), WALA (fallback/comparison) | SootUp is the modern, actively maintained successor to Soot; proven precedent (Steady, Endor, dep-scan use Soot/WALA-class tools for Java). **Flagged 2026-08-01** (see `docs/competitive-landscape-commercial-technical.md` Part 2, not yet independently re-verified): the version pin at `reachability/build.gradle.kts` (1.1.2) was justified only against 1.3.0/2.0.0 and appears stale against the actual current release (reported as 3.0.0); CHA/RTA reportedly truncates at `invokedynamic`/lambda call sites, a concrete false-`Unreachable` risk for lambda-heavy Spring code (see `docs/reachability-caveats.md`); and RTA (already in the same SootUp API family) is reported as an available, low-effort precision upgrade over CHA-only that hasn't been adopted. The documented WALA fallback has no actual dependency in `reachability/build.gradle.kts` today. All of this needs engineering re-validation before acting on it, not just re-stating the finding as fact. |
| **Build/packaging** | **Gradle**, published as a container image + fat JAR | Fat JAR = the CLI; container image = what the GitHub Action runs. |
| **Distribution** | **GitHub Action** (Docker-based) wrapping the **CLI**; CLI also released as a standalone fat JAR / native image | Meets "GitHub Action + CLI." Composite/Docker action so users add ~10 lines of YAML. |
| **XML/JSON parsing** | Jackson (JSON), StAX/Woodstox (streaming FPR/FVDL XML — FPRs can be large) | Streaming avoids OOM on big Fortify exports. |
| **EPSS/KEV** | Direct HTTPS to `api.first.org/data/v1/epss` and CISA KEV JSON; cached to disk with daily TTL | Free, no-auth; never poll per-finding. |
| **Vuln-method signatures** | OSV/GHSA data (OSV API + offline mirror); optional dep-scan/atom slice ingestion | Community-maintained, includes affected functions increasingly. |
| **LLM (fix advisor)** | Provider-abstracted client (Claude via Anthropic API as default reference impl); config via env/secret; **templated fallback** when unset | Keeps the tool usable with zero LLM cost; keeps provider swappable for the community. |
| **PR comment** | GitHub REST/GraphQL via the Action's `GITHUB_TOKEN`; upsert a single marker-tagged comment | Idempotent — no comment spam across pushes. |
| **Testing** | JUnit 5 + a fixtures repo of real-ish Fortify FPR / Black Duck BDIO samples + a deliberately vulnerable Spring Boot app | Golden-file tests for connectors and scoring. |
| **License** | **Apache-2.0** | Permissive, patent grant, community-friendly. |

> If contributor familiarity strongly favors it, the *orchestration/CLI shell* could be Go or Python with the SootUp reachability step invoked as a JVM subprocess. The plan defaults to all-JVM to keep the hardest component in-process; revisit at scaffolding time.

---

## 7. Repository Structure (MVP)

```
reachlayer/
├── LICENSE                        # Apache-2.0
├── README.md
├── PLAN.md                        # this document
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── action.yml                     # GitHub Action definition (Docker-based)
├── Dockerfile                     # builds the action/CLI image
├── build.gradle.kts
├── settings.gradle.kts
├── gradle/ …                      # wrapper
│
├── core/                          # canonical model + orchestration
│   ├── src/main/java/dev/reachlayer/core/
│   │   ├── model/                 # Finding, Location, BlastRadius, FixSuggestion, …
│   │   ├── pipeline/              # Orchestrator wiring ingest→reach→enrich→score→advise→output
│   │   └── config/                # reachlayer.yml loader, scoring weights
│   └── src/test/java/…
│
├── connectors/                    # pluggable scanner ingestion (SPI)
│   ├── api/                       # ScannerConnector interface + Finding SPI
│   ├── fortify/                   # FPR/FVDL XML parser + SSC REST client
│   └── blackduck/                 # BDIO/JSON parser + REST client
│
├── reachability/                  # SootUp call-graph engine
│   ├── src/main/java/dev/reachlayer/reach/
│   │   ├── entrypoints/           # Spring/servlet entry-point discovery
│   │   ├── callgraph/             # SootUp CHA/RTA graph build
│   │   ├── signatures/            # OSV/GHSA vuln-method signature loading + dep-scan slice ingest
│   │   └── ReachabilityTagger.java# intersect graph ∩ signatures ⇒ tag
│   └── src/test/…
│
├── enrich/
│   ├── epss/                      # EPSS client + disk cache (daily TTL)
│   ├── kev/                       # KEV client + diff cache
│   └── blastradius/               # internet-facing / auth / PII / secrets heuristics
│
├── scoring/                       # deterministic blended risk score + explanation
│
├── advisor/                       # LLM fix advisor + templated fallback
│   ├── api/                       # LlmProvider interface
│   ├── providers/                 # anthropic (default), noop/template
│   └── retrieval/                 # advisory text + code-snippet context assembly
│
├── output/
│   ├── api/                       # OutputRenderer interface
│   └── github-pr/                 # single-comment upsert renderer
│
├── cmd/                           # CLI entry point (picocli), builds the fat JAR
│   └── src/main/java/dev/reachlayer/cli/Main.java
│
├── fixtures/                      # test data
│   ├── sample-fpr/                # sample Fortify exports
│   ├── sample-bdio/               # sample Black Duck exports
│   └── vulnerable-spring-app/     # deliberately-vulnerable target for e2e tests
│
├── docs/
│   ├── architecture.md
│   ├── scoring.md                 # exact scoring formula + weights
│   ├── connectors.md              # how to write a new ScannerConnector
│   └── reachability-caveats.md    # soundness/false-negative disclosure
│
└── .github/
    ├── workflows/                 # CI for the project itself + a self-dogfooding demo
    └── ISSUE_TEMPLATE/
```

### Key extension interfaces (defined in MVP even with one impl each)
- `ScannerConnector` → `List<Finding> ingest(Source)` (enables Snyk/Semgrep/Checkmarx later).
- `LlmProvider` → `FixSuggestion suggest(Finding, Context)` (swap Claude/OpenAI/local; noop=template).
- `OutputRenderer` → `void render(RankedReport)` (PR comment now; SARIF/IDE/dashboard later).
- `SignatureSource` → `Set<MethodSig> vulnerableMethods(Component, Cve)` (OSV/GHSA/atom).

---

## 8. Scoring Model (concrete starting point)

Deterministic, explainable, tunable via `reachlayer.yml`. Starting formula (0-100):

```
base        = normalize(CVSS)              # 0-1
exploit     = max(EPSS_percentile, KEV?1.0:0)   # KEV membership pins high
reachMult   = reachable ? 1.0 : unreachable ? 0.4 : 0.7   # unknown ≈ mid
blastMult   = 1 + 0.15*internetFacing + 0.1*touchesAuth
              + 0.1*touchesPII + 0.1*touchesSecrets        # capped at ~1.5

riskScore   = 100 * clamp( (0.5*base + 0.5*exploit) * reachMult * blastMult , 0, 1)
```
- Reachability **down-ranks** but never zeroes (unsound → never hide). KEV/high-EPSS reachable + internet-facing findings float to the top.
- `riskExplanation` records each factor's contribution so developers trust the ordering.
- Weights and multipliers are config, not hardcoded.

---

## 9. Risks & Open Questions

| # | Risk / question | Impact | Mitigation / stance |
|---|---|---|---|
| 1 | **Static reachability is unsound** (reflection, DI, dynamic dispatch, config-driven wiring in Spring) → false negatives, "Unreachable" that is actually reachable. | Could hide real risk if misused. | **Reachability is additive, never suppressive.** Tag `Unknown` liberally; document caveats prominently (`reachability-caveats.md`); default `Unknown` weight stays mid-high. Prefer under-claiming unreachability. |
| 2 | **Vulnerable-method signatures are often coarse.** Many OSV/GHSA advisories lack affected-function granularity. | Falls back to component-level reachability, weaker signal. | Support both granularities; ingest dep-scan/atom slices when available; make signature source pluggable so community can improve it. |
| 3 | **Call-graph construction is slow** on large codebases (1-8 hr scan friction is the very problem we're solving). | Undermines "real-time" promise. | CHA/RTA approximation (not full points-to) in MVP; Phase 1 incremental (IncCHA) graph patching; only analyze **app side** and PR-diff scope; pre-compute where possible. |
| 4 | **Fortify has no lightweight sync PR mode**; SSC completion is poll/webhook with minutes latency. | "Real-time" is aspirational for SAST. | Frame honestly: near-instant for Black Duck Rapid Scan; minutes-latency (poll + webhook fallback) for Fortify. Design as event-driven consumer, not sub-second detector. Webhook reliability unproven → **always keep polling fallback**. |
| 5 | **LLM cost & determinism** for fix suggestions at enterprise finding volumes. | Cost blowup; non-reproducible output. | Only call the LLM for **top-ranked** findings, not all; cache by finding hash; **templated fallback** makes LLM optional; provider-abstracted so orgs use their own/local model. |
| 6 | **Licensing of Fortify/Black Duck API access from a public OSS tool.** Can we redistribute sample FPR/BDIO fixtures? Are there EULA limits on programmatic API use? | Legal/distribution risk. | Consume only **customer-owned exports** at runtime (no vendor data redistributed). Generate **synthetic** fixtures, not real vendor sample files. Legal review before publishing fixtures. Never bundle vendor SDKs. |
| 7 | **EPSS/KEV freshness & availability.** EPSS daily, KEV no webhook. | Stale scores; upstream outage. | Local cache with TTL + graceful degradation (show "score unavailable," never crash). Daily EPSS snapshot, hourly/daily KEV diff. |
| 8 | **Dedup/correlation across two scanners** is genuinely hard (same CVE, different identifiers, SAST-config vs SCA-component). | Duplicate or missed correlation → noise (the thing we fight). | Canonical `Finding.id` hash + CVE/CWE-based correlation; borrow DefectDojo's dedup heuristics as reference; keep it conservative in MVP. |
| 9 | **Scope creep toward becoming a scanner or a gate.** | Loses the neutral-layer differentiator. | Encoded as core principles (§2). Gating and native scanning are explicitly deferred/never. |
| 10 | **Community adoption** — why choose this over DefectDojo + dep-scan glued together? | Project fails to gain traction. | The unique combo (§1): reachability **on Fortify/Black Duck output** + non-blocking inline PR feedback + blast-radius + LLM fixes. Lead with a compelling PR-comment demo on a real vulnerable app. |
| 11 | **Black Duck Detect may already emit its own reachability verdict** (`--detect.impact.analysis.enabled`, per `docs/competitive-landscape-oss.md`), which the `blackduck` connector currently doesn't parse. Not yet verified against a real export (§9 risk 6 forbids using one to check). | If confirmed, Reachlayer's CHA tag and Black Duck's native tag could disagree with no visibility into either. | Flagged in `docs/connectors.md` as an unverified research finding. If confirmed: parse and surface both signals side-by-side, never silently prefer one — same "layer, never replace" stance as everything else in §2. |

**Open questions to resolve at scaffolding time:**
- All-JVM vs. polyglot (JVM reachability subprocess + Go/Python shell)? — default all-JVM (§6).
- Exact Fortify FPR/FVDL schema coverage needed for MVP (which finding fields are load-bearing for scoring)?
- Does the target org already run Black Duck **Rapid Scan** (synchronous) or only full scans? Affects the "real-time" story per install.
- Minimum viable blast-radius heuristic set that's accurate enough to trust — validate on the vulnerable-spring-app fixture.

---

## 10. Immediate Next Steps (for the implementation agent)

1. `git init`; scaffold the repo structure in §7; add Apache-2.0 `LICENSE`, `README.md`, `.gitignore`, Gradle wrapper, `settings.gradle.kts` with the multi-module layout.
2. Define the canonical `Finding` model and the four SPI interfaces (`ScannerConnector`, `LlmProvider`, `OutputRenderer`, `SignatureSource`) — the contracts everything else depends on.
3. Build the **fortify** and **blackduck** offline-export connectors against **synthetic** fixtures.
4. Stand up the **SootUp** reachability engine: Spring/servlet entry-point discovery → CHA call graph → tag against component-level signatures first.
5. Wire EPSS/KEV caches and the deterministic scorer (§8) — get a **ranked list** end-to-end before adding the LLM.
6. Implement the GitHub PR single-comment renderer and the Docker-based `action.yml`.
7. Add the LLM fix advisor last, with the templated fallback as the default path.
8. End-to-end test on `fixtures/vulnerable-spring-app` → open PR → verify the comment appears and the build stays green.
