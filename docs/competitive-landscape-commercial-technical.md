# Competitive & Technical Landscape Assessment

This document is a blunt, source-checked look at (1) where Reachlayer sits relative to commercial
ASPM/reachability products, and (2) whether Reachlayer's specific technical choices (SootUp CHA,
static-only reachability) are still defensible in 2026. It exists to stress-test the claims in
`PLAN.md` §1 and §9 — not to restate them. Where a vendor claim could not be verified from a public,
citable source, that is said explicitly rather than repeated as fact.

Research date: 2026-08-01. Vendor products change quickly; treat specifics as a snapshot.

---

## Part 1: Commercial ASPM landscape

### Summary verdict up front

PLAN.md §1 asserts: "Every commercial ASPM that solves this eventually pressures you to rip out
Fortify and Black Duck and adopt its own native scanners." **This is only true for one of the six
products investigated (Aikido) and partially true for a second (Endor Labs, which ingests but is
now also selling you a replacement SAST engine).** Apiiro, OX Security, Cycode, and Legit Security
all explicitly ingest Fortify and/or Black Duck output as first-class integrations — they are
already doing, at a commercial-product level, the "layer not replace" thing PLAN.md claims is
differentiating. Reachlayer's actual differentiators are narrower than PLAN.md states: it is not
"layer vs. replace" (four of six vendors already layer) — it is **open-source/self-hostable,
PR-native single-comment output with no dashboard, and a public/inspectable scoring formula**,
against products that are closed-source, dashboard-first, and enterprise-sales-only. That is a real
gap, but it is a different gap than the one PLAN.md names, and the document should be corrected.

### Endor Labs

**What's publicly documented about the technical approach:** Endor Labs' own docs
(docs.endorlabs.com/scan/sca/reachability-analysis) describe two modes:
- **Full-scan reachability** — build/compile the project, generate an actual call graph, and check
  whether a path exists from developer code to a vulnerable function. This is comparable in spirit
  to what Reachlayer does with SootUp CHA over app bytecode.
- **Pre-computed reachability** (docs.endorlabs.com/scan/sca/reachability-analysis/pre-computed-reachability/)
  — used as a fallback when the project doesn't build. Endor pre-computes a call graph *for every
  open-source package version in the ecosystem*, stores it, then "stitches" the per-package graphs
  together for a given dependency set at query time, without building the customer's code at all.
  A cited example: the call graph for `logback-access` 1.4.6 alone has 14K+ nodes and 60K+ edges
  across 24 dependencies (Endor Labs blog, "Visualizing the Impact of Call Graphs on Open Source
  Security"). This ecosystem-scale precomputation is Endor's actual moat — it is expensive
  infrastructure (crawl and analyze essentially all of Maven Central/npm/PyPI/etc. ahead of time)
  that an OSS single-repo tool like Reachlayer has no way to replicate and shouldn't try to.
- Endor's own docs use CHA/RTA/VTA terminology (per the Endor Labs "call graph" documentation
  surfaced in this research) but do not publish a precision/recall benchmark or a paper comparing
  their algorithm to CHA/RTA/points-to alternatives — unlike Reachlayer, whose approach (SootUp CHA)
  is at least traceable to a peer-reviewed tool paper (see Part 2).

**Does it ingest Fortify/Black Duck, or does it require replacing them?**
Verdict: **mixed, and moving toward replace.** For SCA, Endor Labs is a replacement scanner, not a
layer — it computes its own SBOM and its own reachability from your build, and there is no public
evidence of a "bring your own Black Duck/Fortify output" ingestion path (searched directly; no
result surfaced this capability, and Endor's GitHub Action / docs describe Endor doing its own
scan). Endor Labs also announced integrated/"AI-native" SAST in 2025-2026
(endorlabs.com "Endor Labs Announces Integrated SAST Offerings"; PR Newswire "Endor Labs Debuts
AI-Native, Multi-Modal SAST") — i.e., they are explicitly building their own SAST to compete with
Fortify/Checkmarx, not to consume Fortify's output. This is the closest of the six vendors to
PLAN.md's "rip out your scanners" characterization, but note it's a genuine technical bet (built to
reason about reachability from source, so it needs its own front end) rather than pure vendor
lock-in for its own sake.

**Pricing/access:** Endor Labs offers a genuinely free tier ("AURI for Developers" — local
scanning, IDE-integrated, read-only vuln data, no account required per Endor's pricing page), but
the team/enterprise tiers ("Core"/"Pro") are seat-priced per code contributor and require a sales
conversation for exact numbers (endorlabs.com/pricing; Vendr marketplace listing). So: individual
developer usage is accessible; team-wide adoption is a commercial negotiation, same as everyone
else here.

### Apiiro

**Ingest vs. replace:** Apiiro is unambiguously a **layer**, and does ingest Fortify by name.
Apiiro markets itself as ingesting, normalizing, deduplicating and risk-scoring findings from
Fortify (including Fortify on Demand), Checkmarx, Veracode, Snyk, SonarQube, GitHub Advanced
Security, Black Duck (Apiiro is a listed Black Duck Technology Alliance Partner), Mend, Wiz, Prisma
Cloud, and bug-bounty/pentest data (apiiro.com/product/integrations/; apiiro.com's "ASPM breakdown"
blog; Black Duck's own integrations page). This directly refutes PLAN.md's blanket claim for this
vendor — Apiiro is doing exactly the "ingest unmodified scanner output, add context, prioritize"
model PLAN.md claims is the gap. What Apiiro adds beyond Reachlayer's scope: a "Risk Graph" of
code-to-cloud context (business criticality, data classification, deployment topology), not
primarily reachability-analysis-as-computed-by-Apiiro — Apiiro's own reachability signal quality
relative to a from-scratch call-graph engine like SootUp is not independently documented in what
was found; it appears to lean more on architectural/design-risk graph context than a from-source
call-graph.

**Pricing/access:** Enterprise-sales-only, no public pricing (multiple sources, e.g. GetApp,
Capterra, g2 all note "contact sales"). Not accessible to a mid-size team without a sales cycle.

### OX Security

**Ingest vs. replace:** **Layer.** OX explicitly integrates with Fortify On Demand, Fortify SSC,
Checkmarx, Coverity, Klocwork, HCL AppScan, Semgrep, SonarQube/SonarCloud, GitHub/GitLab SAST for
SAST, and Black Duck, Checkmarx SCA, Fossa, GitHub Dependabot for SCA (ox.security/integrations/;
OX's own "Top 10 SAST Tools" blog listing its integrations). OX's "PBOM" (Pipeline Bill of
Materials) is explicitly positioned as pulling findings from third-party scanners (Semgrep,
Checkmarx cited by name) into one view and layering its own reachability check ("Code Projection")
on top — checking whether a flagged dependency is actually loaded at runtime and reachable from an
external endpoint. This is functionally close to what Reachlayer claims to be the only OSS tool
doing, except OX does it as a paid, closed, dashboard-centric product and (per its own marketing)
includes a runtime/loaded-at-runtime signal that Reachlayer's static-only approach cannot provide.

**Pricing/access:** No public self-serve pricing found; enterprise engagement model (consistent
with the rest of the category).

### Cycode

**Ingest vs. replace:** **Layer, and explicitly the vendor's core current pitch.** Cycode's
"ConnectorX" is marketed as an open, "click and connect" ASPM connector layer explicitly supporting
Black Duck and 100+ third-party tools (SAST, SCA, secrets, IaC, container) alongside Cycode's own
native scanners (cycode.com "Cycode Introduces a Complete Approach to ASPM"). Cycode also has a
documented Black Duck SCA + Coverity SAST integration article on the Black Duck community site
(community.blackduck.com "Cycode Integration for Black Duck SCA & Coverity"), which is a more
concrete, vendor-to-vendor-documented integration than most competitors have. Direct evidence of a
Fortify-specific connector was not found in this research pass (should be verified against Cycode's
current connector catalog before quoting to a customer), but the "layer over 100+ tools including
Black Duck" claim is well-supported. Note Cycode, like Apiiro/OX, also has its own native scanners
— it's simultaneously a scanner vendor and an aggregation layer, which is a different (dual) model
than Reachlayer's aggregation-only stance.

**Pricing/access:** No public pricing found; sales-engagement model.

### Legit Security

**Ingest vs. replace:** **Layer**, evidenced for Black Duck specifically — Legit's platform update
blog names Black Duck, Snyk Code, and SonarQube as ingested/consolidated/managed sources
(legitsecurity.com blog). No direct evidence of a Fortify-specific Legit connector was found in this
pass; this should be verified before being stated as fact in any customer-facing comparison.

**Pricing/access:** No public pricing found.

### Aikido Security

**Ingest vs. replace:** **The one vendor of the six that matches PLAN.md's "rip and replace"
characterization.** Aikido bundles its own SAST/DAST/SCA/IaC/container/CSPM/runtime scanners built
substantially on open-source scanning engines, and is described (by competitor and neutral
comparison sources, e.g. appsecsanta.com and Aikido's own "Black Duck Alternatives" and
"Blackduck-alternative" comparison pages) as having few-to-no third-party scanner integrations —
it explicitly positions itself as *the* Black Duck/Fortify **alternative** to switch to, not a layer
on top of them. This is the one vendor where PLAN.md's positioning claim is accurate.

**Pricing/access:** This is the one vendor in the set that is genuinely self-serve and
price-transparent: a real free tier (2 users/10 repos, no card), and published flat-rate monthly
plans ($350/$700/$1,050 as of mid-2026, unlimited users, self-serve checkout, no sales call required
for Pro-and-below — aikido.dev/pricing, corroborated by trustradius/spotsaas/codeant summaries).
Ironically, Aikido — the vendor that actually replaces your scanners — is the *most* accessible to
a mid-size team of anything in this survey, which undercuts the framing that accessibility and
"layer not replace" are the same axis.

### Contrast Security — a genuinely different technical approach, not a "better" one

Contrast uses **runtime instrumentation (IAST/RASP)**, not static reachability: an agent
instruments the running JVM (also .NET/Node/Python/Ruby/Go) and observes real data flow and real
method execution during test/production traffic. Contrast SCA specifically "combines static call
graph analysis with runtime execution data" and reports that a large fraction of library code (a
commonly cited Contrast figure is that ~62% of loaded libraries are never invoked at runtime) is
dead weight in typical SCA reports.

**Honest tradeoff, not a ranking:**
- **Runtime (Contrast) advantages:** zero false-positive reachability for anything actually
  observed executing — if the agent saw the vulnerable method get called with attacker-influenced
  input, that's ground truth, not an approximation. It also naturally handles reflection, DI,
  dynamic dispatch, and Spring's config-driven wiring — the exact class of case that PLAN.md's own
  risk #1 flags as SootUp CHA's blind spot (false "Unreachable" from missed dynamic wiring).
- **Runtime (Contrast) disadvantages:** it only knows about code paths that were *actually
  exercised* during instrumented traffic (test suite, staging, or production). Rarely-hit but
  still-reachable code (an admin endpoint no one clicked during the test run, an error-handling
  branch, a feature flag off in staging) is invisible — a false "not reachable" of a different kind
  than static analysis's false negatives, and arguably worse for security because it's silent about
  *why* (no test coverage vs. genuinely unreachable look identical to an IAST-only view unless
  cross-referenced with static analysis).
- **Static (Reachlayer/SootUp) advantages:** broader coverage — every method in the compiled
  bytecode is a candidate, whether or not any test ever hit it; no agent/instrumentation deployment
  needed in production; works pre-deployment, in CI, on a PR diff.
- **Static (Reachlayer/SootUp) disadvantages:** exactly PLAN.md's risk #1 — unsound with respect to
  reflection/DI/dynamic dispatch, so it can produce false "Unreachable" tags for genuinely reachable
  Spring-wired code paths.

Neither approach subsumes the other; a mature program runs both. Reachlayer should describe Contrast
this way in its own docs rather than only positioning against ASPM aggregators — it is not a
competitor to out-argue, it's a complementary technique with an opposite failure mode.

**Pricing/access:** Enterprise-sales-only, no free trial found; Vendr procurement data cited a median
annual contract of roughly $36K (range ~$18K-$148K depending on modules/app count) — not accessible
to a mid-size team without budget approval and a sales cycle.

### Cross-cutting pricing/access finding

Of the seven products reviewed, **only Aikido has genuine self-serve pricing and a usable free
tier**; Endor Labs has a free *individual-developer* tier but team pricing requires sales; every
other vendor (Apiiro, OX, Cycode, Legit, Contrast) is enterprise-sales-only with no public numbers.
This supports PLAN.md §1's cost/access argument for the OSS niche in general, but the framing needs
correcting: the pain isn't "they'll make you switch scanners," it's "they're all priced and gated
like enterprise software, whether or not they replace your scanners." An Apache-2.0, self-hostable,
CI-native tool with a transparent, config-file scoring formula is a real and defensible point of
differentiation against this whole set — just not for the specific reason PLAN.md currently states.

---

## Part 2: Technical landscape for static reachability on the JVM

### State of the art: is CHA still adequate in 2026?

Short answer: **CHA is the correct choice for an MVP that must run fast in CI on arbitrary customer
codebases without a full build, but it is the least precise call-graph algorithm in active use, and
the field has moved well past it for anything claiming to be authoritative.** The academic
literature has treated CHA as the "cheap but imprecise" baseline for over two decades:

- CHA resolves any virtual call site to *every* subtype of the declared receiver type, including
  types that are never instantiated anywhere in the program — this is the classic, long-documented
  source of CHA's imprecision (over-approximation), and is well-established prior art ("Call graph
  construction for Java libraries," Reif et al.; "Systematic Comparison of Six Open-Source Java Call
  Graph Construction Tools," Szabó/Bergmann/et al.).
- **RTA (Rapid Type Analysis)** improves on CHA by restricting candidate receiver types to those
  actually instantiated (`new`) somewhere reachable in the program — strictly more precise than CHA
  at similar cost, and is already listed as available in Reachlayer's own dependency (SootUp
  supports RTA) but is **not what Reachlayer currently uses** per the PLAN/architecture docs (CHA
  only). This is a low-effort, same-framework precision upgrade Reachlayer is leaving on the table.
- **Points-to analysis / k-CFA / VTA** (context-sensitive variants) are meaningfully more precise
  still, propagating actual points-to sets through the program rather than approximating from
  declared types or instantiation sites alone, at real scalability cost (classic reference: Lhoták &
  Hendren, "Scaling Java Points-To Analysis Using SPARK"). SootUp itself now ships a points-to
  analysis path via its "Qilin" module (0-CFA/1-CFA), added in v1.3.0 (June 2023) — again, already
  available in the framework family Reachlayer depends on, unused by Reachlayer today.
- A directly relevant, very recent (April 2026) paper, "Detecting Call Graph Unsoundness without
  Ground Truth" (Zhong, Wold, Windmann; arxiv.org/abs/2604.00885), specifically evaluates SootUp
  against WALA and finds a **large divergence between the two tools' call graphs, driven
  substantially by how each handles `invokedynamic`/lambda call sites**: WALA's representation
  resolves `invokedynamic` bootstrap methods and links lambda call sites to concrete targets, while
  SootUp's CHA/RTA implementation truncates the graph at `invokedynamic` sites (treats them as a
  dummy sink), which means **any lambda-heavy Spring code (method references, functional-interface
  beans, stream pipelines used in request handlers) can silently produce false "Unreachable" results
  in Reachlayer today** — a concrete, citable instance of PLAN.md's own risk #1, not a hypothetical
  one. This is a bigger deal for a Spring codebase than it sounds: modern Spring/Java code leans
  heavily on lambdas and method references in exactly the kind of request-handling and
  filter/interceptor code that determines reachability from an HTTP entry point.
- Practitioner-facing tools that market reachability as their core value prop (Endor Labs, OWASP
  dep-scan/atom, Contrast SCA) have each moved beyond bare CHA: Endor blends ecosystem-precomputed
  call graphs with pre-computed dependency-level fallback; dep-scan's `atom`/`chen` engine is built
  on Joern's Code Property Graph and does **interprocedural taint/data-flow slicing** (source→sink),
  which is a fundamentally different and stronger claim than "is there a call-graph path" — it
  answers "does attacker-controlled input reach the vulnerable sink," not just "is the method
  callable at all." Reachlayer's own PLAN.md (§5 Phase 2) already flags data-flow/taint reachability
  as a future phase and explicitly names dep-scan/atom as prior art to borrow from — this research
  confirms that's the right instinct and that the gap between "CHA reachability" and "taint
  reachability" is real and already exploited by an existing OSS competitor in the same space
  Reachlayer claims to be uncontested in.

**Verdict:** CHA is a legitimate, honest MVP starting point (fast, simple, conservative in the "never
suppress" direction since CHA over-approximates reachability rather than under-approximating it in
most cases) — but the invokedynamic/lambda truncation finding above is the opposite failure mode
(it can *under*-approximate specifically at lambda boundaries), which directly contradicts the
"reachability only down-ranks, never hides, and errs toward Unknown" design intent in PLAN.md §2.3.
This needs to be documented as a known caveat immediately, and RTA (already in the same SootUp
version family) is a strict improvement Reachlayer should adopt before CHA-only, not multi-year
research territory.

### Is SootUp the right library, and is the 1.1.2 pin still justified?

The `reachability/build.gradle.kts` comment pins SootUp 1.1.2 specifically because 1.3.0 changed the
`JavaProject`/`JavaProjectBuilder` API and 2.0.0 renamed artifacts. That reasoning was valid when
written, but **the pin is now significantly stale**: SootUp has since shipped **v2.0.0 (per SootUp's
GitHub releases and Maven Central listings) and a further major version, v3.0.0, released July 16,
2024** — over two years before this research date — which:
- Requires Java 17 as the minimum source/target level,
- Removed the source-code frontend module entirely,
- Reworked the call-graph algorithm itself ("simplify the callgraph algorithm to speed up," and a
  new call-graph pruning feature),
- Merged `AbstractClass`/`SootClass` into `JavaSootClass`, renamed `StmtGraph` to
  `ControlFlowGraph`, and added support for passing explicit class-instance lists into the RTA
  algorithm (i.e., RTA got easier to use in exactly this version family).

None of this was checked against 3.0.0 when the pin comment was written — the comment only reasons
about 1.3.0 vs. 2.0.0, not the version that has actually been the shipping release for two years.
**This is the single most concrete, actionable finding in this whole document**: the "stable,
documented, verified API surface" justification for staying on 1.1.2 needs to be re-validated against
current SootUp (as of this research, 3.0.0), not against a 2023-era comparison of two now-superseded
alternatives. Either the pin is still justified for a *new* reason (e.g., 3.0.0's Java 17 floor is
incompatible with a target customer's toolchain, or a specific 3.0.0 regression was found) — in
which case that reason should replace the current comment — or the pin should be bumped.

On WALA as the documented fallback/comparison tool (per PLAN.md §6): the April 2026 paper above is
direct, recent evidence that **SootUp and WALA are not interchangeable or simply "SootUp primary,
WALA as a sanity-check fallback"** — they diverge structurally on modern bytecode (invokedynamic),
so using WALA as a cross-check would likely surface disagreements that need product-level judgment
calls (which one to trust for a given case) rather than a simple "if they agree, done" arbitration.
This is a documentation gap: PLAN.md names WALA as fallback/comparison but Reachlayer's own
`build.gradle.kts` for the reachability module has no WALA dependency at all today — the WALA
fallback described in the plan does not appear to exist in the code yet, and per this research it
would need real design work (not just "add the jar"), not just implementation time.

### IncCHA / incremental call-graph construction — maturity assessment

IncCHA is real, published, industrially-motivated research — "Incremental Call Graph Construction
in Industrial Practice" (IEEE, ieeexplore.org/document/10172761, also mirrored at Nanjing University's
seg.nju.edu.cn) describes a "reset-recompute" approach: prune call-graph nodes/edges invalidated by a
code change, then re-analyze only the changed region and patch the graph, rather than rebuilding CHA
from scratch. The paper explicitly frames this as motivated by CI/CD-speed program analysis and
reports variants (IncCHAs/IncCHAb) evaluated against full CHA reconstruction. This is squarely
academic/industrial-research-paper maturity, not "here is a maintained open-source library you can
`implementation(...)` today" — no evidence was found in this research of a standalone, maintained,
publicly available IncCHA implementation (as a library, plugin, or product feature) independent of
the paper's own evaluation artifacts. SootUp itself does not appear to ship incremental/patch-based
call-graph construction as a public feature as of the versions checked. **Practical implication for
Reachlayer's Phase 1 roadmap item ("Incremental call-graph construction (IncCHA-style graph
patching)"):** this will likely have to be implemented in-house against SootUp's graph data
structures, informed by the paper's algorithm description, rather than integrated from an existing
tool — budget it as a research-adjacent engineering effort, not a library-integration task. This
matches PLAN.md's own framing (roadmap item, not "download library X"), so no correction needed
there — but the plan should not understate the effort by implying "IncCHA" is a drop-in technique.

---

## What should change in Reachlayer, given this

Ordered by impact, not politeness:

1. **Fix the invokedynamic/lambda gap or document it loudly — this is a live soundness bug, not a
   theoretical risk.** SootUp's CHA/RTA truncates at `invokedynamic`, so any Spring entry point that
   dispatches through a lambda, method reference, or functional-interface bean can be silently
   tagged `Unreachable` when it's actually reachable — directly contradicting the "reachability only
   down-ranks, never hides" principle in PLAN.md §2.3/§9 risk #1. At minimum, add this as an
   explicit, named caveat in `reachability-caveats.md` with a concrete code example; better, detect
   `invokedynamic` call sites during entry-point/call-graph construction and force any finding whose
   only path involves one to `Unknown` rather than `Unreachable`.

2. **Switch from CHA to RTA now, not later.** RTA is in the same SootUp API family Reachlayer
   already depends on (available since ≥1.3.0, and SootUp 3.0.0 specifically improved RTA's
   ease-of-use for exactly this scenario — passing explicit instantiated-class lists). This is a
   precision improvement with no new library, no new research, and modest engineering cost — it
   should not wait for a "Phase 2 taint analysis" horizon.

3. **Re-validate the SootUp version pin.** The 1.1.2 pin's stated justification (comparing only
   against 1.3.0 and 2.0.0) is two major versions and two-plus years out of date relative to the
   actual current release (3.0.0, July 2024). Either re-justify staying on 1.1.2 against 3.0.0
   specifically (e.g., a real incompatibility found during a spike) or upgrade. Leaving a
   stale-by-construction comment in the code is worse than having no comment.

4. **Correct PLAN.md §1's "every commercial ASPM makes you rip out your scanners" claim.** It's
   false for Apiiro, OX Security, Cycode, and Legit Security, all of which explicitly ingest
   Fortify and/or Black Duck as a layer today. The real, defensible differentiator is **open-source,
   self-hostable, PR-native, transparent scoring** vs. **closed-source, dashboard-first,
   enterprise-sales-gated** — true of every vendor surveyed except Aikido's pricing (which is
   self-serve) — not the ingest-vs-replace axis, which four of six vendors already share with
   Reachlayer.

5. **Add Contrast Security to the docs as a complementary technique, not a competitor to
   out-position.** Runtime IAST/RASP and static CHA reachability have opposite failure modes (silent
   under-coverage of unexercised code vs. unsound false-negatives on dynamic dispatch/reflection).
   `reachability-caveats.md` should say this plainly so users running both tools understand why the
   two will disagree on some findings, instead of assuming one of them is simply wrong.

6. **Treat data-flow/taint reachability (Phase 2) as competitively urgent, not just a maturity
   step-up.** OWASP dep-scan's `atom` engine already does Joern-CPG-based interprocedural
   source-to-sink slicing for Java today, in an OSS tool in the same space Reachlayer claims is
   uncontested. "No OSS project does reachability layered on unmodified Fortify/Black Duck output"
   remains true, but "no OSS project does better-than-CHA reachability for Java" is already false —
   Reachlayer's CHA-only approach is the least precise technique among the OSS alternatives it
   itself cites as prior art, not an equal peer to them.

7. **Budget IncCHA as in-house R&D, not integration work.** No maintained, embeddable IncCHA
   implementation exists to depend on; the Phase 1 roadmap item should be scoped as "implement,
   informed by the published algorithm," and estimated accordingly.
