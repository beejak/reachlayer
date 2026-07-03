# Scoring model

Deterministic, explainable, and tunable via `reachlayer.yml`. Implemented in the `scoring`
module (`dev.reachlayer.scoring.RiskScorer`), using weights from
`dev.reachlayer.core.config.ScoringWeights`.

## Formula (PLAN.md §8)

```
base        = normalize(CVSS)                              # 0-1
exploit     = max(EPSS_percentile, KEV ? 1.0 : 0)           # KEV membership pins high
reachMult   = reachable ? reachableMultiplier
              : unreachable ? unreachableMultiplier
              : unknownMultiplier
blastMult   = min(blastRadiusCap, 1
              + internetFacingWeight * internetFacing
              + touchesAuthWeight    * touchesAuth
              + touchesPiiWeight     * touchesPii
              + touchesSecretsWeight * touchesSecrets)

riskScore   = 100 * clamp((cvssWeight*base + exploitWeight*exploit) * reachMult * blastMult, 0, 1)
```

### Default weights

| Weight | Default | Meaning |
|---|---|---|
| `cvssWeight` | 0.5 | Contribution of severity to `base`. |
| `exploitWeight` | 0.5 | Contribution of EPSS/KEV to `base`. |
| `reachableMultiplier` | 1.0 | No down-rank when a call path exists. |
| `unreachableMultiplier` | 0.4 | Down-ranked, never zeroed — static analysis is unsound. |
| `unknownMultiplier` | 0.7 | Mid-high, since "unknown" should not be treated as safe. |
| `internetFacingWeight` | 0.15 | Blast-radius bump if reachable from an HTTP handler. |
| `touchesAuthWeight` | 0.1 | Blast-radius bump if the path touches auth. |
| `touchesPiiWeight` | 0.1 | Blast-radius bump if the path touches PII. |
| `touchesSecretsWeight` | 0.1 | Blast-radius bump if the path touches secrets. |
| `blastRadiusCap` | 1.5 | Ceiling on the combined blast-radius multiplier. |

### `base` (severity normalization) fallback chain

Fortify SAST findings usually carry no CVSS (Fortify's native severity is a 0.0-5.0 float, not a
CVE/CVSS score). `RiskScorer` normalizes whatever severity signal is available, in order:

1. Known CVSS (`Cvss.isKnown()`): `base = clamp(score / 10.0, 0, 1)`.
2. Otherwise, if `severity()` parses as a number, treat it as Fortify's 0.0-5.0 scale:
   `base = clamp(value / 5.0, 0, 1)`.
3. Otherwise, keyword-match the severity text: critical→0.9, high→0.7, medium/moderate→0.4,
   low→0.15, info(rmational)→0.05.
4. Otherwise, default to `0.5` (a documented neutral midpoint — never silently `0`).

## `riskExplanation`

Every scored finding carries a `RiskExplanation` recording each factor's raw value and how it
was derived (which branch of the fallback chain, whether KEV pinned `exploit`, which reachability
tag drove `reachMult`, which blast-radius flags contributed to `blastMult`) so the ranking in the
PR comment is auditable, not a black box.

## Configuration

All weights are overridable via `reachlayer.yml`:

```yaml
scoring:
  unreachableMultiplier: 0.2   # e.g. down-rank unreachable findings harder
  blastRadiusCap: 2.0
```

Any field omitted (or the file itself being absent) falls back to the defaults above — the
scorer is fully functional with zero configuration.
