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

## The other direction: CHA can also over-claim `reachable`

Everything above is about false negatives (`unreachable` when it's actually reachable). The
opposite failure mode also matters and, prior to this note, wasn't documented here: **CHA is a
coarse, over-approximating algorithm, so it can also tag something `reachable` when the specific
conditions needed to actually trigger it are not met at runtime** — e.g. a vulnerable method is on
*a* call path from an entry point, but only under a configuration flag, request parameter, or
branch condition CHA has no way to model (CHA reasons about "is there any static call edge," never
about "under what runtime conditions"). Semgrep's public critique of call-graph-only ("transitive")
reachability — [see their engineering blog](https://semgrep.dev/blog/2024/overrated-and-underperforming-transitive-reachability-analysis/),
surfaced via `docs/competitive-landscape-oss.md` — argues this makes CHA-only tools over-claim
"reachable" more often than dataflow/taint-based tools do.

For Reachlayer specifically this is **lower-stakes than it would be for a suppressive tool**,
because `reachable` only affects ranking/grouping (principle 3, above) and never hides or removes a
finding — an over-claimed `reachable` finding is mis-ranked, not hidden. But mis-ranking is still a
real cost to the product's core value proposition (prioritization), so treat a surprising
`reachable` tag with the same skepticism as a surprising `unreachable` one: it means "a call path
exists," not "this is definitely exploitable right now." Phase 2's planned taint/data-flow mode
(PLAN.md §5) is the intended fix; no code change has been made for this yet.

## A fixed gap: `invokedynamic`/lambda call sites

**Fixed, 2026-08-01** (previously confirmed-but-unfixed the same day; before that, only a flagged,
unverified research citation — see history below). SootUp 1.1.2's stock
`ClassHierarchyAnalysisAlgorithm` has **no invokedynamic or lambda-metafactory resolution at all**:
decompiling `sootup.callgraph-1.1.2.jar`'s `resolveCall` method shows it explicitly special-cases
`invokedynamic` call sites (`JDynamicInvokeExpr`) to return zero call targets, unconditionally.
`CallGraphBuilder` now uses `dev.reachlayer.reach.callgraph.LambdaAwareChaAlgorithm` instead — a
small subclass that overrides that one case. SootUp's own ASM-based bytecode frontend already
parses a `LambdaMetafactory`-bootstrapped `invokedynamic` site's bootstrap arguments into a typed
`sootup.core.jimple.common.constant.MethodHandle` carrying the real implementation method's
signature directly — no custom bytecode/constant-pool parsing was needed, just overriding the one
line of SootUp's algorithm that discards it.

A dedicated fixture — `fixtures/vulnerable-spring-app`'s `LambdaDispatchController.reachViaLambda()`,
a genuine Spring MVC entry point that calls `LambdaVulnerableComponent.unsafeMethod()` through a
`java.util.function.Supplier` lambda — is now correctly tagged `REACHABLE`
(`ReachabilityTaggerFixtureIT#resolvesCallEdgesThroughALambdaDispatchNowThatTheGapIsFixed`), where
it was previously (correctly, at the time) asserted `UNREACHABLE` as a confirmed, reproduced bug.

**What this does and doesn't cover:** only `invokedynamic` sites whose bootstrap arguments contain
a `MethodHandle` with a resolvable target method signature are handled — this covers ordinary
lambda expressions and method references compiled the standard `javac` way. Not every
`invokedynamic` site is a lambda: Java 9+ string concatenation also compiles to `invokedynamic`
(bootstrapped via `StringConcatFactory`, which has no "target method" the way a lambda does), and
`LambdaAwareChaAlgorithm` correctly falls back to the stock (empty-edge) behavior for those rather
than crashing or guessing — see
`ReachabilityTaggerFixtureIT#nonLambdaInvokedynamicCallSitesDoNotCrashCallGraphConstruction`
(exercises a real `StringConcatFactory`-bootstrapped entry point,
`StringConcatController.concat()`). This class never removes a call edge the stock algorithm would
have found — it only adds ones for the specific case the stock algorithm silently dropped.

If you still hit a surprising `unreachable` tag on lambda/method-reference-heavy code after this
fix, it's more likely one of the other unsoundness sources documented above (reflection, DI,
config-driven dispatch) than this specific gap.

<details>
<summary>History: unverified citation → confirmed bug → fixed</summary>

A background research pass into the current (2026) state of the art for JVM call-graph
construction (`docs/competitive-landscape-commercial-technical.md` Part 2) originally reported this
as a claim sourced from elsewhere, not independently re-verified against SootUp's source by hand.
It was then reproduced directly against a real fixture and the actual dependency jar (confirmed,
same day), and shortly after that, fixed via `LambdaAwareChaAlgorithm`, all as described above.
</details>

## Mitigating undiscovered entry points via configuration

A related but distinct gap from the ones above: `EntryPointScanner`'s built-in discovery only
recognizes `main`, Spring MVC handler methods, and direct `HttpServlet` subclass overrides. A
message-queue listener, a `@Scheduled` method, or any other runtime dispatch mechanism outside
those three is invisible to it, which can itself cause a genuinely reachable finding to be tagged
`unreachable` — not because CHA failed to trace a call edge (the `invokedynamic` gap above), but
because the entry point that would have seeded that call path was never discovered in the first
place. `reachlayer.yml`'s `entryPoints` section lets an operator patch this without touching
Reachlayer's code — see [`docs/configuration.md`](configuration.md) for the full reference. This
does not make discovery sound, it only widens the set of *known* entry points to what an operator
tells it about.

## Practical guidance

- Treat `reachable` as meaningful signal ("we found a concrete call path").
- Treat `unreachable` as "we looked and didn't find a path" — a hint, not a proof. It is
  appropriate to prioritize other findings first, not to ignore this one.
- Treat `unknown` as "we couldn't determine this" — weight it close to `reachable` when triaging
  manually, since the pipeline already does the same.
- Multi-language, taint/data-flow reachability (higher precision, still not soundness) is a
  Phase 2 item (PLAN.md §5) — out of scope for this MVP.
