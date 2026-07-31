# SARIF output

`output/sarif`'s `SarifOutputRenderer` writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
JSON file summarizing every finding in a `RankedReport` — the same static-analysis interchange
format GitHub's code-scanning feature consumes.

Reachlayer's job stops at writing that file to disk. It does **not** call GitHub's SARIF upload
API itself (that would duplicate an Action GitHub already publishes and maintains, and would be
scope creep beyond "render SARIF"). To get GitHub code-scanning annotations from the file
Reachlayer produces, add one more step to your workflow after the Reachlayer Action step:

```yaml
- uses: reachlayer/reachlayer@v0
  with:
    fortify-fvdl: audit.fvdl
    blackduck-bdio: scan.json
    sarif-out: reachlayer-report.sarif
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reachlayer-report.sarif
```

Or from the standalone CLI:

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --sarif-out reachlayer-report.sarif
```

This, like every other `OutputRenderer`, is strictly additive/advisory — GitHub code-scanning
annotations from an uploaded SARIF file do not fail a build any more than the PR comment does; see
`PLAN.md` principle 1.

## Mapping notes

- One SARIF *rule* per distinct `{source}:{CWE-or-CVE-or-slugified-title}` — repeated instances of
  the same underlying issue across files are grouped under one rule, not duplicated.
- `message.text` always includes the risk score, reachability tag, and fix suggestion.
- SCA findings that lack a file/line (the common case — Black Duck findings are usually
  component-level) get a synthetic `dependencies/<coordinate>` location, flagged
  `reachlayerSyntheticLocation: true` in the result's `properties`, rather than being omitted.

See `docs/superpowers/specs/2026-07-31-sarif-output-renderer-design.md` for the full design
rationale.
