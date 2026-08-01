# Competitive Landscape — Open Source (and adjacent commercial) Reachability/Triage Tools

This document is a blunt, evidence-based assessment of where Reachlayer sits relative to the
existing OSS (and closest commercial) landscape, written against the specific positioning claim in
`PLAN.md` §1:

> "No existing OSS project combines (a) real-time, non-blocking, developer-facing PR/IDE feedback,
> (b) reachability/exploitability reasoning layered on **unmodified** Fortify + Black Duck output,
> (c) attack-surface/blast-radius context, and (d) actionable per-finding fix guidance."

Research date: 2026-08-01. Sources are linked inline; where a source could not be fetched directly
(HTTP 403 from vendor site), findings are corroborated via search-engine summaries of the same page
and cross-checked against a second source where possible.

---

## 1. DefectDojo (`DefectDojo/django-DefectDojo`)

**What it actually does:** DefectDojo is a Django-based, self-hosted vulnerability
management/ASPM platform. It ingests findings from 200+ scanner parsers — including native
[Fortify](https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/fortify/) and
[Black Duck](https://docs.defectdojo.com/supported_tools/parsers/api/blackduck/) (both file-import
and API forms) — normalizes them into a common finding model, and gives teams a dashboard for
triage, backlog tracking, and reporting. Its dedup engine (`docs.defectdojo.com` — Hash Code /
Unique ID algorithms) computes a configurable hash per scanner (`HASHCODE_FIELDS_PER_SCANNER`) and
supports "cross-tool" deduplication, but only via the Hash Code algorithm since different tools
rarely expose compatible native IDs — this is a real, working, but admittedly blunt correlation
mechanism, not semantic CVE/CWE matching.

In May 2025 DefectDojo Pro (the paid tier) added ["risk-based
prioritization"](https://www.businesswire.com/news/home/20250513967867/en/DefectDojo-Unveils-Risk-Based-Prioritization-Capability-to-Strengthen-Unified-Vulnerability-Management)
that factors in "exploitability, reachability, revenue impact, compliance penalties" — but this is
consuming/aggregating externally-supplied signals (e.g., from a connected scanner or feed) into a
scoring model, not computing a call graph itself. DefectDojo does not build or ship a static
reachability *engine*; it is a signal consumer, and the reachability-aware tier is Pro-only
(commercial), not part of the open-source core.

The core CI integration is a report-uploader (`DefectDojo Actions`, `DefectDojo-CLI-Action`) used
in gating workflows, not a PR-comment bot. There is no first-party "post a single advisory PR
comment" renderer; any PR-comment behavior is bolted on separately via generic GitHub PR-comment
actions.

**Comparison to Reachlayer's niche:**
- Has: far broader scanner ingestion breadth (200+ parsers vs. Reachlayer's 2), a real
  cross-scanner dedup engine, backlog/SLA tracking, a mature dashboard, multi-year production
  track record.
- Lacks (in the OSS core): any static reachability computation of its own, blast-radius reasoning,
  LLM-generated fix suggestions, and native non-blocking PR-comment output.
- DefectDojo Pro (commercial) is closing part of the gap with reachability-*aware scoring*, but
  still as a consumer of someone else's reachability signal, and still dashboard/backlog-first, not
  PR-native.

**Verdict:** PLAN.md's characterization ("DefectDojo ingests both scanners but is a batch dashboard
with no reachability") is **accurate for the OSS core** and mostly still accurate for Pro (Pro
*scores* reachability inputs but does not *compute* reachability). This part of the positioning
claim holds.

---

## 2. OWASP dep-scan / atom (`owasp-dep-scan/dep-scan`)

**What it actually does:** OWASP dep-scan (formerly AppThreat depscan, donated to OWASP in 2023,
NLnet-funded, ~1.3k GitHub stars, actively released — v6.x as of mid-2026) is a dependency/SCA audit
tool. It accepts local repos, container images, Kubernetes manifests, OS packages, and CycloneDX
SBOMs as input. **It does not ingest Fortify FPR or Black Duck BDIO/JSON as a native input format**
— confirmed directly from the project README/docs
([depscan.readthedocs.io](https://depscan.readthedocs.io/reachability-analysis/),
[github.com/owasp-dep-scan/dep-scan](https://github.com/owasp-dep-scan/dep-scan)). PLAN.md's claim
here is verified correct.

Its reachability approach is genuinely more advanced than a plain CHA call graph: the companion
tool **atom** builds a language-agnostic intermediate representation and performs static *usage
slicing* (not just call-graph reachability) for JVM, JS/TS, Python, and PHP, with
language-specific engines for other ecosystems (Rusi for Rust, Golem for Go, Dosai for .NET).
Critically, dep-scan computes the reachable-code slice **independently of any vulnerability
database**, then intersects it with CVE/advisory data afterward — this avoids a common trap where
reachability tooling is gated by how well a vulnerability DB happens to document affected function
names (the same problem Reachlayer's `PLAN.md` §9 risk #2 identifies for OSV/GHSA). This is
architecturally more mature than Reachlayer's MVP plan, which explicitly falls back to
component-level (not slice/method-level) reachability when OSV/GHSA lacks function granularity.

**Comparison to Reachlayer's niche:** dep-scan/atom's reachability is more technically sophisticated
per-language than Reachlayer's SootUp CHA (7 language ecosystems vs. 1; usage-slicing vs.
CHA-approximation), and PLAN.md itself proposes optionally *consuming* dep-scan/atom's reachables
slice as a signature source — implicitly conceding dep-scan is ahead on the reachability technique
itself. What it does not do is ingest, correlate, or add context to existing Fortify SAST / Black
Duck SCA output, has no blast-radius layer, no LLM fix advisor, and no PR-comment renderer (dep-scan
is a CLI/CI audit tool with SARIF/JSON/HTML output, not an advisory-comment system).

**Verdict:** True as stated in PLAN.md — dep-scan does reachability but not Fortify/Black Duck
ingestion. However, it should be read as a **stronger, not weaker, reachability engine** than
Reachlayer's CHA-only MVP; if dep-scan/atom is not actually would-be integrated per §4/§9, Reachlayer
risks shipping a technically inferior reachability signal under a superficially similar label.

---

## 3. Semgrep Supply Chain (reachability analysis)

**What it actually does:** Semgrep Supply Chain (part of the Semgrep AppSec Platform, not the
free/OSS Semgrep CLI core) scans a repo's own dependency manifests and source and performs
reachability analysis to filter which vulnerable-library findings are actually exploitable. As of
2024–2025 it moved from "reachable = imported/called" heuristics to **dataflow reachability**:
cross-function, cross-file taint tracking that traces whether attacker-influenceable input actually
flows into the vulnerable sink, not just whether the vulnerable function is merely called
([Semgrep product update, 10-language dataflow reachability
announcement](https://semgrep.dev/blog/2024/semgrep-supply-chain-announces-dataflow-reachability-support-for-10-languages/);
[Semgrep reachability whitepaper](https://semgrep.dev/assets/content/whitepapers/semgrep-reachabilityanalysis-whitepaper-1225.pdf)).
This is a meaningfully more precise technique than call-graph-only (CHA/RTA) reachability.

Notably, Semgrep's own blog explicitly attacks the category Reachlayer's MVP sits in: ["Overrated and
underperforming: transitive reachability
analysis"](https://semgrep.dev/blog/2024/overrated-and-underperforming-transitive-reachability-analysis/)
argues that call-graph-only reachability (no dataflow) frequently mislabels vulnerabilities as
reachable when specific parameter/config conditions required for exploitation are not met — i.e., it
is prone to *false positives on "reachable"*, not just false negatives on "unreachable." That's a
different failure mode than the one PLAN.md §9 risk #1 worries about (static analysis missing real
reachability), but it is a direct, credible critique of the exact analysis class (CHA-level call
graph, no taint) Reachlayer's MVP ships.

**Licensing reality:** Semgrep Supply Chain and its reachability feature are **not part of the
free/open-source Semgrep CLI**. They live behind the commercial Semgrep AppSec Platform (free for
teams ≤10 contributors/10 private repos, then $35/contributor/month Team tier, Enterprise beyond
that). Semgrep the *engine* is open source; Semgrep *reachability* is not.

**Comparison to Reachlayer's niche:** Semgrep Supply Chain scans dependencies **it discovers
itself** from your repo — it is not built to ingest and enrich pre-existing Fortify/Black Duck
findings. It is a competing/replacing SCA product, not an additive layer over other scanners' output.
It also doesn't touch SAST findings.

**Verdict:** Not a direct competitor to Reachlayer's specific niche (it replaces rather than layers
on Fortify/Black Duck), and it is not open source in the piece that matters (reachability). But it
is technically superior on the actual reachability technique (dataflow vs. CHA), and its own
marketing/engineering blog is a useful, credible source of skepticism about CHA-only reachability
claims that Reachlayer should not ignore.

---

## 4. CodeQL and the GitHub code-scanning ecosystem

**What it actually does:** CodeQL is GitHub's own SAST engine (query-based dataflow/taint analysis
over a compiled code database), shipped via `github/codeql-action`. It is a scanner, producing SARIF
that lands in GitHub's native code-scanning UI — it is not a triage layer over *other* scanners'
output.

No evidence was found of a GitHub-native or community project that takes Fortify or Black Duck
output and re-triages/re-scores it using CodeQL or the code-scanning API as the reachability engine.
GitHub's own recent investment in this space (e.g., Copilot Autofix, the GitHub Security Lab
"Taskflow Agent" for [AI-supported vulnerability
triage](https://github.blog/security/ai-supported-vulnerability-triage-with-the-github-security-lab-taskflow-agent/))
is aimed at triaging *CodeQL's own* findings, not third-party scanner output, and is not a general
Fortify/Black Duck ingestion layer.

**Verdict:** Confirmed not a direct competitor, as PLAN.md assumes — but worth flagging that GitHub
is actively building AI-assisted triage for its own scanner, which is the same category of feature
(reduce SAST noise, explain why a finding matters) Reachlayer builds for Fortify/Black Duck. If
GitHub extends Taskflow-style triage to arbitrary SARIF-uploaded findings (Fortify and Black Duck
can both emit/be converted to SARIF for code scanning), that would directly encroach on Reachlayer's
space. No evidence this has happened yet as of this research.

---

## 5. Trivy, Grype, and other OSS SCA scanners

**Confirmed: neither Trivy nor Grype does component-level reachability against a real call graph.**
Multiple independent sources agree these are pure vulnerability-database matchers (SBOM/package
manifest → CVE lookup), with no code-level call graph construction
([safeguard.sh Trivy-vs-Grype writeup](https://safeguard.sh/resources/blog/trivy-vs-grype-buyer-comparison-2026),
[AppSec Santa OSS SCA roundup](https://appsecsanta.com/sca-tools/open-source-sca-tools)). This part
of Reachlayer's differentiation claim (vs. "pure SCA scanners") is not undermined.

**The structurally closest existing analog to Reachlayer's model was found here, not among Fortify/Black Duck tools**:
[Safeguard](https://safeguard.sh) is described as explicitly *not* replacing Trivy/Grype detection —
it ingests their SBOM/scan output, deduplicates across repos, applies its own reachability analysis
on top, and correlates with CISA KEV — i.e., the exact "layer on top of an existing SCA scanner's
unmodified output, add reachability + exploitability + ranking" pattern Reachlayer proposes for
Black Duck. However, Safeguard is a **commercial product** (not open source), targets Trivy/Grype
(not Fortify/Black Duck), and no independent technical detail on its reachability engine internals
was found beyond marketing copy — so it should be read as "proof this pattern has commercial
demand and a working precedent," not as a mature open technical benchmark.

**Verdict:** True as stated for Trivy/Grype themselves. But the *category* of "reachability bolted
onto a scanner's unmodified output" already has a commercial precedent (Safeguard, for
Trivy/Grype) — Reachlayer would be the first to apply that pattern to Fortify/Black Duck
specifically and the first to do it as OSS, but it would not be inventing the pattern itself.

---

## 6. Direct search for "reachability" + "Fortify" or "Black Duck" (GitHub-wide)

Searched via GitHub's code and repository search APIs directly (not just web search) for
combinations of `reachability` with `Fortify`/`FPR`/`Black Duck`/`BDIO`. Result: **no OSS project
combining reachability analysis with Fortify or Black Duck ingestion was found** — abandoned, small,
or otherwise. The matches that surfaced were false positives (glibc `_FORTIFY_SOURCE` compiler
hardening flags, unrelated "Reachability" networking libraries, "Fortify" as an English word) or
generic FPR-file parsing utilities with no reachability logic
([python-fortify](https://github.com/gfdsa/python-fortify), [fortipy](https://github.com/nicolasrod/fortipy),
[Vulnerator](https://github.com/Vulnerator/Vulnerator) — all simple FPR readers/report converters).

**The one genuinely relevant finding, and arguably the most important one in this whole
investigation, is not a third-party OSS project — it's the vendors themselves:**

- **Black Duck already computes and ships its own reachability signal.** Black Duck Detect has a
  native "Vulnerability Impact Analysis" feature
  ([blackduck.com blog](https://www.blackduck.com/blog/vulnerability-reachability-in-sca.html),
  [Black Duck docs](https://verint.app.blackduck.com/doc/Risk/VulnImpact.html)) that builds a call
  graph (via `--detect.impact.analysis.enabled`) to determine whether a vulnerable method is on an
  execution path from the application's own code, tagging findings "reachable" down to the calling
  method and line number. **This is scoped to Java projects today — the exact same language
  Reachlayer's MVP targets** — and is populated via a mix of Synopsys/Black Duck's own static
  analysis and human curation. This is not third-party OSS, but it means the "unmodified Black Duck
  output" Reachlayer plans to ingest may **already contain a reachability verdict**, at least for
  some Java components, that Reachlayer's SootUp CHA engine would otherwise recompute from scratch
  without checking for or reconciling with it.
- **Fortify (OpenText) is shipping its own AI-agent-based exploitability/reachability triage skill.**
  [`fortify/skills`](https://github.com/fortify/skills) (MIT-licensed, ~16 stars, 41 commits — small
  but real and vendor-maintained) includes a `fortify-exploitability-analysis` skill that
  "batch-triages a list of known CVEs/GHSAs for reachability across a codebase," sourcing CVEs from
  SBOMs, Fortify on Demand releases, or SSC application versions, and emitting per-CVE reports plus
  combined CycloneDX VEX output. It does **not** ingest Black Duck, and it is an interactive AI-agent
  capability invoked by a human/agent session (e.g., via Claude Code or Copilot), not an automated
  PR-comment bot — so it is not doing what Reachlayer does end-to-end. But it establishes that
  Fortify's own vendor is already building exploitability/reachability triage tooling around its own
  scanner, on the same premise Reachlayer is built on (SBOM/CVE list → reachability triage →
  actionable output), just not (yet) as a non-blocking PR-native, cross-scanner (Fortify+Black Duck)
  product.

**Verdict on the exact niche claim:** For genuine third-party open-source projects, PLAN.md's claim
is **true** — nothing combining reachability with Fortify or Black Duck ingestion exists in OSS,
abandoned or otherwise. But the claim needs a caveat: **both vendors are independently encroaching
on this exact niche from the inside** — Black Duck with native Java call-graph reachability already
shipped, Fortify with an early-stage AI-triage skill. Reachlayer's true differentiator is not "does
reachability where none existed" so much as "does reachability that is (a) cross-scanner —
correlates Fortify SAST with Black Duck SCA in one view, (b) vendor-neutral/OSS, (c) automated and
PR-native rather than a manual/interactive skill or a Java-only per-scanner add-on."

---

## Summary table

| Project | OSS? | Ingests Fortify+BD unmodified? | Computes reachability? | Technique | PR-native advisory output? | Blast-radius / LLM fix? |
|---|---|---|---|---|---|---|
| **DefectDojo** (core) | Yes | Yes (both) | No | — | No (dashboard/gate actions) | No |
| **DefectDojo Pro** | No (commercial) | Yes (both) | No (consumes external signal) | — | No | Partial (risk scoring only) |
| **OWASP dep-scan/atom** | Yes | No | Yes | Usage-slicing per language (atom) | No (CLI/SARIF/HTML) | No |
| **Semgrep Supply Chain** | No (platform-gated) | No (scans its own detected deps) | Yes | Dataflow/taint reachability | Partial (PR checks, not advisory-only) | Partial (AI triage assistant) |
| **CodeQL / GH code scanning** | Yes (engine) | No | N/A (is a SAST engine) | — | Via code-scanning UI, not PR comment | No |
| **Trivy / Grype** | Yes | No | No | — | No | No |
| **Safeguard** (Trivy/Grype layer) | No (commercial) | No (targets Trivy/Grype) | Yes (undisclosed technique) | Unknown | Unclear | Partial (KEV correlation, auto-fix) |
| **Black Duck native (Vuln Impact Analysis)** | No (vendor feature) | N/A (it's the source) | Yes, Java only | Call graph + human curation | No | No |
| **Fortify `fortify-exploitability-analysis` skill** | Yes (MIT) | No (Fortify-only, no BD) | Yes (interactive) | Unspecified/agent-driven | No (manual invocation) | No |
| **Reachlayer** | Yes | Yes (both) | Yes | SootUp CHA (unsound, additive) | Yes (single upserted comment) | Yes (heuristic blast-radius, LLM-or-template fix) |

---

## Does PLAN.md §1's positioning claim hold?

**Mostly true, with one real crack.** No open-source project — abandoned or active — combines
reachability analysis with Fortify and/or Black Duck ingestion the way Reachlayer plans to. That
part of the claim is solid and was directly verified via GitHub code/repo search, not just marketing
copy. DefectDojo's OSS core genuinely has no reachability engine; dep-scan genuinely doesn't ingest
Fortify/Black Duck; Trivy/Grype genuinely have no call graph. The claim as literally written
survives scrutiny.

The crack: the claim is implicitly "no one else is doing reachability *for these two scanners'
findings*," but it undersells that **both vendors are already moving into this space themselves**,
and one of them (Black Duck) has already shipped a real, non-hypothetical, code-path-verified,
line-number-accurate reachability tag for Java — the same MVP language target. Reachlayer's true,
defensible differentiator is narrower than PLAN.md states: not "reachability on Fortify/Black Duck
output" in the abstract, but specifically **cross-scanner correlation + neutrality + non-blocking
PR-native delivery + blast-radius + LLM fixes**, none of which the vendor-native features offer. That
narrower claim is still true and still a real gap. The broader claim ("no reachability layer exists
for these scanners' output at all") is weakened, not falsified.

Separately, on pure technical merit, Reachlayer's reachability *implementation* (SootUp CHA, one
language) is behind the state of the art represented by dep-scan/atom (multi-language usage-slicing)
and Semgrep Supply Chain (dataflow/taint across 10+ languages) — both of which exist and are
production-used today. Reachlayer is not introducing a novel reachability technique; it is
repackaging a known-weaker technique (CHA) around a novel *input* (Fortify+Black Duck) and a novel
*delivery mechanism* (single non-blocking PR comment). That's a legitimate, marketable niche — but
it should be described as "packaging/positioning innovation," not "reachability innovation," when
talking to a technical audience who already knows Semgrep's and dep-scan's numbers.

---

## What should change in Reachlayer, given this landscape

Prioritized, concrete:

1. **Check whether Black Duck's own export (BDIO/REST) already carries a reachability/impact-analysis
   verdict for Java components** (populated when `--detect.impact.analysis.enabled` was used
   upstream). If so, the Black Duck connector should parse and surface it as a corroborating signal
   (agree/disagree with SootUp's own tag) rather than silently ignoring data already present in the
   "unmodified" export — this is both more honest to the "layer, never replace" principle and cheap
   to implement relative to the value (a disagreement between Black Duck's reachability tag and
   Reachlayer's own is itself a useful, explainable signal).
2. **Stop marketing "reachability" as the novel part; market "cross-scanner correlation +
   PR-native, non-blocking delivery" as the novel part.** Update `PLAN.md` §1/§9 risk #10 to name
   dep-scan/atom, Semgrep Supply Chain, Black Duck's native impact analysis, and Fortify's
   `exploitability-analysis` skill explicitly as prior art on the reachability *technique*, and
   reposition Reachlayer's pitch around what none of them do: unify Fortify SAST + Black Duck SCA
   into one risk-ranked, blast-radius-aware, LLM-explained, non-blocking PR comment.
3. **Revisit the CHA-only reachability plan in light of Semgrep's own public critique** of
   call-graph-only reachability (over-claims "reachable" without checking whether attacker-relevant
   parameters/conditions are met). Since Reachlayer's design already treats reachability as additive
   and non-suppressive, over-claiming "reachable" is lower-stakes for Reachlayer than for tools that
   use reachability to *hide* findings — but it still degrades the ranking quality that's the whole
   value proposition. Phase 2's planned taint/data-flow mode should be pulled forward in priority, or
   at minimum `reachability-caveats.md` should explicitly cite this false-positive-on-reachable
   failure mode (currently the doc, per PLAN.md §9 risk #1, only discusses false negatives).
4. **Seriously evaluate ingesting OWASP dep-scan/atom's reachables slice as a signature/verdict
   source for Java**, as PLAN.md §4 already floats as optional — given atom's usage-slicing is more
   mature than CHA and is free/OSS, this could raise Reachlayer's actual reachability quality without
   building a second engine from scratch, and would be a legitimate, citable OSS collaboration rather
   than a from-scratch reimplementation of dep-scan's work.
5. **Watch, don't panic about, GitHub's Taskflow-style AI triage.** It is not yet a general
   SARIF/Fortify/Black Duck ingestion product, but GitHub extending Copilot Autofix/Taskflow triage
   to arbitrary uploaded SARIF (which both Fortify and Black Duck can emit) is the most plausible
   "someone bigger builds exactly this" risk on the horizon; no action needed now beyond monitoring.
6. **Do not lead a pitch deck or README with "no one else does reachability for SAST/SCA."** It's
   defensible in the narrow, literal sense verified here, but any technically literate reader will
   immediately think of Semgrep, Snyk, or Endor Labs and conclude the claim is either uninformed or
   deliberately narrow-scoped in a way that reads as spin. Lead with the cross-scanner + non-blocking
   PR-native combination instead, which is the part that actually held up under this research.
