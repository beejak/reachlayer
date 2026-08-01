# Connectors

A connector normalizes one scanner's native export into the canonical
`dev.reachlayer.core.model.Finding` model, without modifying the scanner's own severity/CVSS
judgement (PLAN.md §2 principle 2). This is the plugin point future scanners (Snyk, Semgrep,
Checkmarx, ...) attach to.

## The `ScannerConnector` SPI

```java
public interface ScannerConnector {
    String sourceName();                 // e.g. "fortify"
    boolean supports(ScanSource source);  // by extension/content sniff
    List<Finding> ingest(ScanSource source) throws ConnectorException;
}
```

`ScanSource` wraps a local file `Path` plus free-form metadata. `Orchestrator` tries every
registered connector's `supports(...)` against every input source and calls `ingest(...)` on the
ones that match; a single connector's failure is logged and skipped, never fatal.

## `fortify` — Fortify FVDL/FPR

- Fortify's native export is `audit.fvdl` (XML), optionally wrapped in a `.fpr` zip archive
  alongside other artifacts (source archive, engine data, ...). This connector accepts either: a
  raw `.fvdl` file, or a `.fpr` — in which case it unzips just the `audit.fvdl` entry in-memory
  and ignores everything else in the archive.
- Parsing is **streaming** (StAX via Woodstox, per PLAN.md §6) rather than a DOM load, since FPRs
  from large codebases can be big. Only the fields load-bearing for the pipeline are extracted:
  `ClassInfo` (kingdom/type/subtype/analyzer/default severity/CWE), `InstanceInfo`
  (instance id/severity/confidence), the primary `SourceLocation` (file/line/snippet), and the
  `Description[@classID]/Abstract` text.
- Fortify SAST findings carry **no CVE/CVSS** — `cvss` is always `Cvss.UNKNOWN` for `fortify`
  findings; `severity` is kept as Fortify's native 0.0-5.0 float, stringified as-is (never
  re-bucketed into Critical/High/Medium/Low by Reachlayer — see PLAN.md §3.3, `severity` is
  "scanner-reported, kept as-is, never overridden").
- Real Fortify FVDL does not always carry CWE directly (it usually requires a Rulepack taxonomy
  lookup from kingdom/type/subtype). The synthetic fixture and this MVP parser include an
  optional `<ClassInfo><CWE>` element directly for simplicity; a production-grade connector would
  add a taxonomy mapping table as a follow-up.

Fixtures: `fixtures/sample-fpr/audit.fvdl` (synthetic, hand-written — **not** real Fortify
output; see PLAN.md §9 risk 6 on vendor data licensing).

## `blackduck` — Black Duck BDIO/JSON

- Real Black Duck BDIO output is a JSON-LD dependency graph, with vulnerability data typically
  fetched separately via REST. For MVP readability, this connector accepts a simplified,
  flattened JSON shape carrying the same load-bearing fields per component: name, version,
  ecosystem, and a list of `{cveId, cwe, severity, cvssScore, cvssVector, description}` entries.
  One `Finding` is emitted per (component, vulnerability) pair.
- Swapping in a full BDIO JSON-LD reader (or the real Black Duck Rapid Scan REST response shape)
  later only changes this connector's parsing internals — the `Finding` contract, and everything
  downstream of it, is unaffected.

Fixtures: `fixtures/sample-bdio/scan.json` (synthetic, hand-written — **not** a real Black Duck
export).

### Flagged research finding: Black Duck Detect already emits its own reachability verdict

A background competitive-research pass (`docs/competitive-landscape-oss.md`) surfaced that Black
Duck's own scanner, Detect, ships a native call-graph-based reachability feature for Java —
"Vulnerability Impact Analysis" (`--detect.impact.analysis.enabled`) — that tags components as
reachable/unreachable in the Detect output itself. If that field is present in a real,
customer-run Black Duck export, this connector currently ignores it entirely: `BlackDuckConnector`
only reads `name`/`version`/`ecosystem`/the vulnerability list per component, with no field for a
vendor-supplied reachability verdict.

This has **not been independently verified against a real Black Duck export** (per this project's
own no-real-vendor-data rule — see `CONTRIBUTING.md`) — treat it as a flagged, high-priority item
to validate, not a confirmed gap. If confirmed, the implication is direct: Reachlayer's own
CHA-based `ReachabilityTagger` result and Black Duck's native verdict could disagree, and silently
preferring one over the other (or ignoring one) would undercut the "layer, never replace" principle
(PLAN.md §2) just as much as re-bucketing a scanner's severity would. The right fix, if this is
confirmed, is almost certainly to parse and surface Black Duck's verdict as a second, clearly
labeled signal alongside Reachlayer's own tag — not to replace either with the other.

## Writing a new connector

1. Implement `ScannerConnector` in a new module (`connectors:<name>`), depending on `core` (and
   optionally `connectors:api` for shared helpers like CVE/CWE extraction regexes and severity
   normalization in `dev.reachlayer.connectors.api.ConnectorSupport`).
2. Register the module in `settings.gradle.kts` and wire an instance into `cmd`'s connector list.
3. Never invent or override a scanner-reported severity/CVSS value — pass it through as-is.
4. Prefer streaming parsers for formats that can be large (XML: StAX/Woodstox; JSON: Jackson
   streaming API) to avoid OOM on big exports, though a tree-model parse is acceptable for
   MVP-sized inputs (as `blackduck` does).
5. Add synthetic fixtures under `fixtures/sample-<name>/` — never redistribute real vendor sample
   data (PLAN.md §9 risk 6).
