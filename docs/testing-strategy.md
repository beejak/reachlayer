# Testing strategy: unit tests vs. evals

Reachlayer has two distinct test layers. Don't confuse them.

## Unit tests (per module, `src/test/java`)

Fast, deterministic, one-class-at-a-time. They verify code *correctness*: does `RiskScorer`
implement the formula in `docs/scoring.md` exactly, does `ReachabilityTagger` degrade to
`UNKNOWN` when call-graph construction fails, does `Orchestrator` skip a failing connector. Run
via `./gradlew test` (part of `./gradlew build`).

## Evals (`evals` module)

Verify system *quality* against a labeled corpus and against naive baselines — questions a unit
test can't answer:

- Is reachability tagging actually accurate against known reachable/unreachable code
  (`ReachabilityAccuracyEvalTest`, backed by `ReachabilityCorpus`)?
- Does the blended risk score actually beat naive CVSS-only sorting, or is the added complexity
  not earning its keep (`RiskRankingEvalTest`, backed by `RankingScenario`)?
- Does the pipeline genuinely never crash on bad/adversarial input
  (`NeverFailBuildInvariantTest`, backed by `NeverFailScenarios`)?

Each eval asserts a hard floor as a normal JUnit `assertThat(...)` — e.g. zero false negatives on
`REACHABLE`-labeled corpus cases, or Reachlayer's precision@3 strictly beating the CVSS-only
baseline's on a hand-crafted scenario.

## Two different "build"s — don't conflate them

**Eval test failures fail Reachlayer's own CI build (`./gradlew build`)**, exactly like a unit
test failure would. That is Reachlayer's own engineering quality bar.

This is a completely separate concept from PLAN.md principle 1, Reachlayer's *product* guarantee
that it will **never fail a customer's build** at runtime. A regression that makes an eval fail
here should stop *this* repo's CI — that's the whole point. It must never be read as "therefore
the tool is allowed to crash when a customer runs it against their own repo." That guarantee is
enforced separately, at the orchestration level, by `Orchestrator`'s per-stage `safeStage`/
`renderAll` guards — which is exactly what `NeverFailBuildInvariantTest` regression-tests.

## Scoreboard

`./gradlew :evals:runEvals` regenerates `evals/scoreboard.md`, a plain-Markdown summary
(reachability confusion matrix, baseline-vs-Reachlayer precision@3, never-fail-invariant
pass/fail) for humans to skim. It is intentionally **not** wired into `build`/`check` — it's a
side-effecting artifact regenerated on demand, so normal `./gradlew build` runs stay fast and
don't mutate the working tree. CI runs it as a separate, non-blocking, informational step (see
`.github/workflows/ci.yml`) and posts it to the job summary.

## Growing the corpus

`ReachabilityCorpus` and `RankingScenario` should only grow. Every real reachability
false-positive/false-negative found in the wild becomes a new permanent `LabeledCase`; every
ranking scenario that trips up the scorer becomes a new permanent finding in `RankingScenario`.
Cases are never removed, even after the underlying bug is fixed — removing one would silently
delete regression coverage for a defect that was once real.
