# Contributing to Reachlayer

Thanks for considering a contribution. This project is small and the bar is: does your change
make the tool more correct, more useful, or easier to understand — without violating the
non-negotiable design principles in [`README.md`](README.md) (never fail the build, never
suppress a finding, layer never replace).

## Setup

Requires JDK 21. No other tooling is required.

```bash
git clone https://github.com/reachlayer/reachlayer.git
cd reachlayer
./gradlew build   # compiles every module and runs the full test suite
```

See the [README's "Getting started"](README.md#getting-started--the-short-version) section for
running the CLI itself.

## Before you open a PR

1. `./gradlew build` passes locally — every module, no exceptions.
2. New behavior has a test. This repo has no exceptions to "write a test first" for anything
   beyond a pure doc change — see `docs/success-criteria.md` for the concrete bar every change is
   held to.
3. If you're touching a scanner connector, a `--classes`/reachability code path, or an output
   renderer, run the manual end-to-end check described in `docs/evaluation-pipeline.md` — it
   catches integration issues unit tests alone can miss.
4. Update the relevant doc in `docs/` alongside the code change. Stale docs are treated as bugs
   in this repo, not a follow-up task.

## What to avoid

- **No real vendor scanner output**, ever — not as a fixture, not as a test case, not "just to
  check something locally" if you plan to commit it. Fortify/Black Duck export files are licensed
  tool output and may contain real, confidential vulnerability data about someone's real codebase.
  All fixtures in this repo are synthetic or hand-written; see `PLAN.md` §9 risk #6.
- **No merge-gating behavior.** Any change that could cause Reachlayer to fail a CI check or
  block a merge is out of scope — this is a hard, non-negotiable design principle, not a
  preference.
- **No new dependency without a reason stated in the PR description.** This repo is deliberately
  light on dependencies; see how sparingly `fixtures:corpus-generator` and `core.baseline` were
  built (plain string/JSON building, no new library) as the default bar to clear before reaching
  for one.

## Code style

Match the surrounding code. A few patterns are load-bearing across this codebase, not just style
preference:
- Constructor injection for I/O boundaries (see any `enrich/*` client) so tests can fake the
  boundary without a mocking framework — this repo uses none.
- New optional pipeline stages are added via a new constructor **overload**, not by changing an
  existing constructor's signature, whenever more than one existing call site would otherwise need
  to change (see `core.pipeline.Orchestrator`'s baseline-stage addition for the precedent, and
  `docs/lessons-learned.md`'s entry on why).
- Every stage/renderer degrades on failure — log a warning, never propagate an exception that
  would abort the run.

## Questions

Open an issue. There is no chat/Discord for this project at this size.
