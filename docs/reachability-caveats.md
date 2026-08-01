# Reachability: soundness caveats

**Static reachability analysis in Reachlayer is unsound.** This is expected and by design — see
PLAN.md §2 principle 3 and §9 risk 1. This document exists so nobody mistakes an `unreachable` or
`unknown` tag for a guarantee.

## Why it's unsound

The `reachability` module builds a CHA (Class Hierarchy Analysis) call graph via SootUp from
discovered entry points (`main`, Spring MVC `@RequestMapping`-family annotated handlers,
`HttpServlet.doGet`/`doPost` overrides) and checks whether a vulnerable method/class is present
among the transitively reachable methods. This approach **cannot see**:

- **Reflection** — `Class.forName(...)`, dynamic proxies, reflective method invocation.
- **Dependency injection / Spring wiring** — beans wired by configuration, classpath scanning,
  conditional `@Bean` definitions, AOP proxies — CHA does not resolve Spring's DI graph.
- **Config-driven dispatch** — e.g. a class name read from a properties file and instantiated at
  runtime.
- **Dynamic class loading, serialization-driven instantiation, native code, and dynamic
  dispatch edge cases** CHA's conservative call-graph resolution doesn't fully model.

Any of these can mean a method Reachlayer tags `unreachable` is, in fact, reachable at runtime —
a **false negative**.

## What Reachlayer does about it

1. **Reachability is additive, never suppressive.** The tag affects ranking (via the
   `reachMult` scoring factor — see `scoring.md`) and PR-comment grouping only. It never removes
   a finding from the output. Every finding Fortify/Black Duck reported is still visible in the
   full ranked list, `unreachable`-tagged or not.
2. **`unknown` is used liberally, and weighted accordingly.** Whenever call-graph construction
   fails, a component/class can't be resolved in the analyzed bytecode, or a SAST finding's
   source location can't be mapped to a class, the tag is `unknown` (multiplier 0.7 by default —
   closer to "reachable" than "unreachable") rather than guessing `unreachable`.
3. **`unreachableMultiplier` down-ranks but never zeroes** (0.4 by default, not 0) — an
   unreachable-tagged finding can still surface if its severity/exploitability is high enough.
4. **Component-level fallback.** Many OSV/GHSA advisories lack function-level granularity
   (PLAN.md §9 risk 2); when a `SignatureSource` can't name the specific vulnerable method, it
   falls back to "is *any* method of this component reachable" — coarser, but conservative in the
   safe direction (a class-level match is easier to satisfy than a specific-method match, so it
   under-claims `unreachable`, not `reachable`).
5. **CHA over full points-to analysis** (PLAN.md §9 risk 3) — CHA is a fast, standard,
   *over-approximating* algorithm: it tends to add more call edges than a more precise analysis
   would, which biases it toward reporting things as reachable rather than missing them. This
   partially offsets (but does not eliminate) the false-negative risk above.

## A specific, researched gap: `invokedynamic`/lambda call sites

A background research pass into the current (2026) state of the art for JVM call-graph
construction (see `docs/competitive-landscape-commercial-technical.md` Part 2 — not independently
re-verified against SootUp's source by hand, but cites a specific, checkable source) reports that
SootUp's CHA/RTA implementation truncates the call graph at `invokedynamic` call sites (treating
them as a dummy sink) rather than resolving the lambda/method-reference bootstrap target, unlike
WALA which does resolve them. If accurate, this means **a Spring entry point that dispatches
through a lambda, method reference, or functional-interface bean can be silently tagged
`unreachable` when it is in fact reachable** — a concrete instance of the false-negative risk this
document already describes in general terms above, but specifically triggered by a coding style
(functional/lambda-heavy handlers) that is extremely common in modern Spring code, not an obscure
edge case.

This has not yet been reproduced against a local test fixture or fixed in `ReachabilityTagger` —
treat it as a flagged, high-priority research finding to validate and address (see `PLAN.md`
Phase 1/2), not yet a confirmed-and-patched bug. If you hit an `unreachable` tag on code you know
dispatches through a lambda or method reference, this is the first thing to suspect.

## Practical guidance

- Treat `reachable` as meaningful signal ("we found a concrete call path").
- Treat `unreachable` as "we looked and didn't find a path" — a hint, not a proof. It is
  appropriate to prioritize other findings first, not to ignore this one.
- Treat `unknown` as "we couldn't determine this" — weight it close to `reachable` when triaging
  manually, since the pipeline already does the same.
- Multi-language, taint/data-flow reachability (higher precision, still not soundness) is a
  Phase 2 item (PLAN.md §5) — out of scope for this MVP.
