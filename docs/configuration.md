# Configuration (`reachlayer.yml`)

A single optional YAML file, passed via `--config <path>` (or `config-path` in `action.yml`).
Every field is optional at every level — a missing section, a missing field within a section, or
the file being entirely absent all fall back to documented defaults, so the tool is fully
functional with zero configuration. Implemented by `dev.reachlayer.core.config.ConfigLoader`,
loading into `dev.reachlayer.core.config.ReachlayerConfig`. See [`reachlayer.yml`](../reachlayer.yml)
at the repo root for a runnable, fully-commented example.

## `scoring`

Tunable weights for the deterministic risk formula — see [`docs/scoring.md`](scoring.md) for the
full formula and what each weight means. All ten fields are optional; any field left out keeps its
documented default.

## `advisor`

| Field | Default | Meaning |
|---|---|---|
| `provider` | `"noop"` | Which `LlmProvider` to use: `"noop"` (templated fix suggestions, no API key needed) or `"anthropic"` (requires `ANTHROPIC_API_KEY`). |
| `topNForLlm` | `5` | Only the top-N ranked findings get a real LLM call; the rest use the templated fallback (PLAN.md §9 risk 5 — never call the LLM for every finding). |

## `output`

| Field | Default | Meaning |
|---|---|---|
| `topN` | `5` | How many findings are shown in full detail in the primary PR-comment table before the rest collapse into a `<details>` section. |
| `commentMarker` | `"<!-- reachlayer:report -->"` | The HTML comment used to find and upsert Reachlayer's own PR comment rather than creating a duplicate — see `docs/lessons-learned.md`'s pagination-bug entry for why this matters. |

## `entryPoints`

Patches a specific, documented gap: `EntryPointScanner`'s built-in discovery only recognizes
`main`, Spring MVC handler methods, and direct `HttpServlet` subclass overrides (see
[`docs/reachability-caveats.md`](reachability-caveats.md)). Anything else the runtime can invoke
directly — a Kafka/JMS listener, a `@Scheduled` method, a custom framework's own dispatch
mechanism — is invisible to it, which can cause a genuinely reachable finding to be tagged
`unreachable`. Both lists default to empty; adding entries here never removes or weakens the
built-in discovery, it only adds to it.

| Field | Default | Meaning |
|---|---|---|
| `extraAnnotations` | `[]` | Fully-qualified, dot-separated annotation class names (e.g. `"org.springframework.scheduling.annotation.Scheduled"`). Any method carrying one of these annotations, on **any** class, is treated as an entry point — not limited to `@Controller`/`@RestController` classes. |
| `extraClasses` | `[]` | Fully-qualified, dot-separated class names. **Every public method** declared directly on one of these classes is treated as an entry point (constructors and static initializers are excluded). |

Example:

```yaml
entryPoints:
  extraAnnotations:
    - "org.springframework.scheduling.annotation.Scheduled"
  extraClasses:
    - "com.example.jobs.NightlyReportJob"
```

A method matching both an `extraClasses` and an `extraAnnotations` rule is only counted once — the
two overlapping does not produce a duplicate entry point.

**What this does not do:** it does not make reachability analysis sound (PLAN.md §9 risk 1 still
applies in full — this only widens the set of *known* entry points, it can't discover ones an
operator doesn't tell it about), and it is not a substitute for the invokedynamic/lambda gap fix
tracked in `docs/reachability-caveats.md` (a lambda-dispatched call from an already-discovered
entry point is a different problem than an *undiscovered* entry point, and this feature only
addresses the latter).

## `suppression`

Display-only noise reduction — PLAN.md §2 principle 3 ("never suppress a finding") still applies
in full. This section can only ever affect what `MarkdownReportFormatter` puts in its rendered
table; it never removes a finding from the underlying `RankedReport`, never affects the SARIF
renderer, the baseline store, or pipeline metrics. Every finding Fortify/Black Duck reported is
still counted in the summary line's total, still in the SARIF output, still in `--metrics-out`
— a suppressed-from-display finding is hidden from one table, not deleted from the run.

| Field | Default | Meaning |
|---|---|---|
| `displayCwes` | `{}` | Map of CWE id (e.g. `"CWE-563"`) to a **required** human-readable reason. Any finding carrying that CWE is excluded from the rendered Markdown table(s). |

Example:

```yaml
suppression:
  displayCwes:
    "CWE-563": "Team decision: unused-variable warnings are pure lint noise here (JIRA-1234)"
```

The reason is required, not optional, so a suppression rule is always self-documenting — a future
reader of `reachlayer.yml` (or the PR comment itself) can always see *why* a CWE was hidden, not
just that it was. When a suppression rule actually hides at least one finding in a given run, the
rendered report includes a disclosure line naming how many findings were hidden and why, e.g.:

> 1 finding suppressed from this display by policy (still counted above and in the full
> SARIF/metrics output): CWE-563 (Team decision: unused-variable warnings are pure lint noise
> here (JIRA-1234))

A `displayCwes` entry for a CWE that doesn't appear in a given run's findings produces no
disclosure line at all — only CWEs that actually mattered for that specific report are mentioned,
not the whole configured list.

**What this does not do:** it is not a merge-gate mechanism (PLAN.md §2 principle 1 — Reachlayer
never fails or blocks a build regardless of what's configured here), and it does not change
severity, CVSS, or risk score — a suppressed-from-display finding still contributes its real score
to every other output surface exactly as if this section didn't exist.
