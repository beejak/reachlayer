# Baseline/diff mode

`core.baseline`'s `BaselineStore`/`BaselineDiffer`, wired through `cmd`'s `--baseline-in` /
`--baseline-out` flags (and `action.yml`'s matching inputs), let a Reachlayer run tag every
finding as *new* (introduced since a prior baseline run) or *pre-existing*. The rendered PR
comment then foregrounds new findings in the primary table, while still fully listing pre-existing
ones in a collapsed section — never dropping data, per `PLAN.md` principle 3.

A baseline is a small JSON file containing the set of finding ids from a prior run:

```json
{
  "generatedAt": "2026-07-31T12:00:00Z",
  "findingIds": ["fortify-1a2b3c", "blackduck-4d5e6f"]
}
```

Finding ids are already stable across independent runs (`Finding.stableId(...)`, hashed from
source + rule + location + component), so two separate scans of the same underlying finding
always produce the same id — no extra correlation step is needed to diff them.

## What Reachlayer does — and does not — do

Reachlayer's job is exactly two primitives: **given a baseline file, diff against it** (
`--baseline-in`), and **given a request to write one, write it** (`--baseline-out`). Deciding
*which branch counts as the baseline*, triggering a second scan, and passing the resulting file
between two CI jobs is entirely your workflow's concern — Reachlayer does not detect base
branches or orchestrate multi-job scans itself (that would duplicate what your CI system already
does well, and is scope creep beyond "diff findings").

## Example: a two-job GitHub Actions pattern

```yaml
name: reachlayer

on:
  push:
    branches: [main]
  pull_request:

jobs:
  baseline:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan main and capture a baseline
        uses: reachlayer/reachlayer@v0
        with:
          fortify-fvdl: audit.fvdl
          blackduck-bdio: scan.json
          baseline-out: reachlayer-baseline.json
          post-pr-comment: "false" # no PR to comment on for a push-to-main scan
      - uses: actions/upload-artifact@v4
        with:
          name: reachlayer-baseline
          path: reachlayer-baseline.json

  pull-request:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download the base-branch baseline
        uses: dawidd6/action-download-artifact@v6 # or any artifact-from-another-workflow action
        with:
          workflow: reachlayer.yml
          branch: ${{ github.event.pull_request.base.ref }}
          name: reachlayer-baseline
        continue-on-error: true # first-ever PR against a branch with no prior baseline: proceed undiffed
      - name: Scan the PR and diff against the baseline
        uses: reachlayer/reachlayer@v0
        with:
          fortify-fvdl: audit.fvdl
          blackduck-bdio: scan.json
          baseline-in: reachlayer-baseline.json # missing/absent file degrades gracefully to "no baseline"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Or from the standalone CLI:

```bash
# Base-branch job:
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --baseline-out reachlayer-baseline.json

# PR job, after downloading reachlayer-baseline.json from the base-branch job's artifact:
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --baseline-in reachlayer-baseline.json
```

## Rendering

- When no baseline is used (`--baseline-in` omitted or its file missing/unreadable), the rendered
  report is identical to a normal Reachlayer run — nothing changes.
- When a baseline is used, the report's primary table shows only new findings, risk-ranked; any
  additional new findings beyond the configured top-N are in their own collapsible "Show all N new
  findings" block; every pre-existing finding is still fully listed, in a separate collapsible
  "Pre-existing findings (unchanged from baseline)" block. If the PR introduces nothing new, the
  report says so explicitly instead of showing an empty table.

See `docs/superpowers/specs/2026-07-31-baseline-diff-mode-design.md` for the full design
rationale.
