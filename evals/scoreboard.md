# Reachlayer eval scoreboard

_Generated: 2026-07-03T03:15:25.061291500Z_

See `docs/testing-strategy.md` for what this measures and why it's separate from unit tests.

## Reachability tagging accuracy

Corpus: `ReachabilityCorpus` (2 labeled case(s)). Positive label = `REACHABLE`.

| Metric | Count |
|---|---|
| True positives (reachable, correctly tagged reachable) | 1 |
| False positives (not-reachable ground truth, tagged reachable) | 0 |
| True negatives (not-reachable, correctly not tagged reachable) | 1 |
| False negatives (reachable ground truth, NOT tagged reachable) | 0 |

Hard floor (`ReachabilityAccuracyEvalTest`): zero `REACHABLE`-labeled cases are ever tagged `UNREACHABLE` — under-claiming unreachability is the safe direction (PLAN.md §9 risk 1).

## Risk ranking: Reachlayer vs. naive CVSS-only baseline

Scenario: `RankingScenario` (6 hand-crafted findings), scored against a hand-labeled ground-truth top-3.

| Ranking | Precision@3 |
|---|---|
| CVSS-only baseline | 0.33 |
| Reachlayer (`RiskScorer`) | 1.00 |

Hard floor (`RiskRankingEvalTest`): Reachlayer's precision@3 must be strictly greater than the CVSS-only baseline's on this scenario.

## Never-fail-build invariant

Scenarios exercised: 7

**PASS** — no scenario let an exception escape `Orchestrator.run` (PLAN.md §2 principle 1).
