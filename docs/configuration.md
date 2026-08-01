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
