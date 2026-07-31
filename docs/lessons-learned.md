# Lessons learned

Running log of concrete, falsifiable things learned while building Reachlayer — not general advice,
only things that changed a decision or caught a real bug. Newest entries first.

## 2026-07-31 — SARIF output renderer (Phase 1, first item)

- **A test's `ObjectMapper` must mirror production's serialization config, or null-omission
  assertions lie.** `SarifReportBuilderTest` originally used a bare `new ObjectMapper()` to
  re-serialize `SarifModel.SarifLog` for assertions, while `SarifOutputRenderer` (production)
  configures `JsonInclude.Include.NON_NULL`. The bare mapper serialized an absent `region` as an
  explicit JSON `null` instead of omitting the field, so `node.at("/.../region").isMissingNode()`
  was false when it should have been true — a real failure, not a flaky test. Fix: the test's
  static `MAPPER` now applies the same `NON_NULL` inclusion as the renderer. Lesson: when a test
  re-parses a model's own serialized form to assert structure, match the *production* mapper
  config exactly, or the test is validating a different format than what ships.

- **This sandbox blocks live EPSS/KEV HTTP calls (`403` at the proxy tunnel)** — confirmed by
  running the built CLI for real, not just via fake `HttpFetcher`s in unit tests. This was the
  intended non-blocking-degradation path (PLAN.md §9 risk #7) exercising itself: `EpssClient`
  fell back to cache, `KevClient` fell back to an empty result, and the process still exited `0`
  and produced a complete, correctly-scored report and a valid SARIF file. Useful to know before
  assuming a manual end-to-end run "isn't testing anything real" just because it can't reach the
  internet — the graceful-degradation contract is exactly what such a run proves.

- **SARIF rule-id deduplication by CWE (not by CVE or per-finding) collapses unrelated CVEs that
  share a root cause into one GitHub Security-tab rule.** In the fixture run, `CVE-2021-44228`
  (Log4Shell) and `CVE-2019-12384` (Jackson polymorphic deserialization) both carry `CWE-502`
  (deserialization of untrusted data) and were correctly merged into a single
  `blackduck:CWE-502` rule with two results — this is desired grouping, not a collision bug, but
  it means "one rule per CVE" is the wrong mental model for this renderer; it's "one rule per
  underlying weakness class."

- **A read-only planning agent (no `Write`/`Edit` tools) cannot save its own output** — it can
  only return the full file contents as text in its final report. When delegating a "write a
  design spec and plan" task to such an agent, the orchestrating session must relay and save that
  text itself; don't assume the files exist on disk just because the agent reports paths it
  "wrote."

- Phase 0 (the MVP) was already fully implemented before this session started — 7,211 lines of
  Java, all modules wired end-to-end via `cmd`'s `Main`. Worth checking `git log` and actual
  module contents before assuming a `PLAN.md` roadmap item is unstarted; the roadmap doc lags
  implementation reality.
