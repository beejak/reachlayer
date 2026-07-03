# cmd CLI Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `dev.reachlayer.cli.Main` (a picocli CLI) plus a small `EnrichmentPipeline` composition class in the `cmd` module, wiring every already-implemented pipeline module (`connectors`, `reachability`, `enrich`, `scoring`, `advisor`, `output`) through `core`'s existing `Orchestrator`, so the CLI contract already documented in `README.md` and `action.yml` becomes real.

**Architecture:** Two new classes in `cmd/src/main/java/dev/reachlayer/cli/`: `EnrichmentPipeline` (implements `core.pipeline.EnrichmentStage`, composes `EpssClient` + `KevClient` + `BlastRadiusAnalyzer`) and `Main` (picocli `Callable<Integer>`, parses CLI flags, builds every `Orchestrator` stage via small package-private static factory methods that take injectable I/O dependencies — this is what makes the wiring testable without any live network call).

**Tech Stack:** Java 21, picocli (already a `cmd` dependency), JUnit 5 + AssertJ (already the repo-wide test stack), Jackson (transitively via `core`/`connectors:blackduck`).

## Global Constraints

- No changes to any module other than `cmd` — every class this plan wires already exists with the constructor/method signatures shown below (verified by direct reading, not guessed).
- No live network calls in any automated test — every HTTP-touching class (`EpssClient`, `KevClient`) is exercised only via fake `HttpFetcher` lambdas, exactly like `enrich:epss`'s and `enrich:kev`'s own existing tests.
- CLI flags must exactly match what `action.yml`'s `args:` list already invokes: `--fortify=`, `--blackduck=`, `--repo=`, `--classes=`, `--config=`, `--post-pr-comment=`, `--out=`, all always passed (blank string means "not provided", never an error). One additive flag, `--cache-dir`, is new and not referenced by `action.yml`.
- Never fail the build: `Main.call()` always returns exit code `0` for any exception raised while running the pipeline itself (matches `Orchestrator`'s own internal safety net and PLAN.md principle 1). Picocli's own non-zero exit for malformed CLI arguments, which happens before `call()` runs, is left untouched.
- Follow existing test conventions exactly: `@TempDir Path tempDir` for anything touching disk, JUnit 5 `@Test`, AssertJ `assertThat`, fake dependencies as lambdas at the true I/O boundary.

---

## Reference: exact signatures this plan wires together

Copied verbatim from the source files (all already exist, already compile, already have their own passing tests):

```java
// core/src/main/java/dev/reachlayer/core/pipeline/Orchestrator.java
public Orchestrator(
        List<ScannerConnector> connectors,
        ReachabilityStage reachabilityStage,
        EnrichmentStage enrichmentStage,
        ScoringStage scoringStage,
        AdvisorStage advisorStage,
        List<OutputRenderer> outputRenderers,
        ReachlayerConfig config)
public RankedReport run(List<ScanSource> sources, String repoLabel)

// core/src/main/java/dev/reachlayer/core/pipeline/{ReachabilityStage,EnrichmentStage,ScoringStage}.java
// all @FunctionalInterface: List<Finding> -> List<Finding>
// core/src/main/java/dev/reachlayer/core/pipeline/AdvisorStage.java also: List<Finding> -> List<Finding>

// core/src/main/java/dev/reachlayer/core/config/ConfigLoader.java
public static ReachlayerConfig loadDefaults()
public static ReachlayerConfig load(Path path) throws IOException

// core/src/main/java/dev/reachlayer/core/spi/ScanSource.java
public static ScanSource ofPath(Path path)

// connectors/fortify/.../FortifyConnector.java — public FortifyConnector()
// connectors/blackduck/.../BlackDuckConnector.java — public BlackDuckConnector()

// reachability/src/main/java/dev/reachlayer/reach/ReachabilityTagger.java
public ReachabilityTagger(Path classesRoot, List<SignatureSource> signatureSources)
// implements ReachabilityStage directly (has a `tag(List<Finding>)` method satisfying it)

// reachability/src/main/java/dev/reachlayer/reach/signatures/ComponentLevelSignatureSource.java
public ComponentLevelSignatureSource() // implements SignatureSource

// enrich/epss/src/main/java/dev/reachlayer/enrich/epss/EpssClient.java
public EpssClient(HttpFetcher httpFetcher, Path cacheDir)
public Map<String, Epss> lookup(List<String> cveIds) // never throws
// dev.reachlayer.enrich.epss.HttpFetcher: String fetch(URI uri) throws IOException — SAM
// dev.reachlayer.enrich.epss.JdkHttpFetcher: public JdkHttpFetcher()

// enrich/kev/src/main/java/dev/reachlayer/enrich/kev/KevClient.java
public KevClient(HttpFetcher httpFetcher, Path cacheDir)
public boolean isKnownExploited(String cveId) // never throws, false on null
// dev.reachlayer.enrich.kev.HttpFetcher: String fetch(URI uri) throws IOException — SAM (DIFFERENT type than epss's)
// dev.reachlayer.enrich.kev.JdkHttpFetcher: public JdkHttpFetcher()

// enrich/blastradius/src/main/java/dev/reachlayer/enrich/blastradius/BlastRadiusAnalyzer.java
public BlastRadiusAnalyzer() // no-arg
public BlastRadius analyze(Finding finding) // never throws

// scoring/src/main/java/dev/reachlayer/scoring/RiskScorer.java
public RiskScorer() // no-arg
public List<Finding> score(List<Finding> findings, ScoringWeights weights)

// advisor/api/src/main/java/dev/reachlayer/advisor/api/FixAdvisorService.java
public FixAdvisorService(LlmProvider provider, AdvisorConfig config, ContextBuilder contextBuilder, Path repoRoot)
// implements AdvisorStage (has advise(List<Finding>))
// advisor/api/src/main/java/dev/reachlayer/advisor/api/retrieval/ContextBuilder.java — public ContextBuilder()

// advisor/providers/noop/.../NoopLlmProvider.java — public NoopLlmProvider() // implements LlmProvider
// advisor/providers/anthropic/.../AnthropicLlmProvider.java
public static AnthropicLlmProvider fromEnvironment() // reads ANTHROPIC_API_KEY / ANTHROPIC_MODEL

// output/api/src/main/java/dev/reachlayer/output/api/ConsoleOutputRenderer.java
public ConsoleOutputRenderer(PrintStream out, Path outputFile) // outputFile nullable = console-only
// implements OutputRenderer

// output/github-pr/.../GitHubPrCommentRenderer.java
public static GitHubPrCommentRenderer fromEnvironment(GitHubApiClient client)
// throws IllegalStateException if GITHUB_REPOSITORY / GITHUB_PR_NUMBER env vars missing/malformed
// output/github-pr/.../GitHubRestApiClient.java
public static GitHubRestApiClient fromEnvironment() // throws IllegalStateException if GITHUB_TOKEN missing

// core/src/main/java/dev/reachlayer/core/model/Finding.java
public List<String> cve() // never null, may be empty
public Finding.Builder toBuilder()
// Finding.Builder: epss(Epss), kev(boolean), blastRadius(BlastRadius), build()

// core/src/main/java/dev/reachlayer/core/config/ReachlayerConfig.java
public record ReachlayerConfig(ScoringWeights scoring, AdvisorConfig advisor, OutputConfig output)
// core/src/main/java/dev/reachlayer/core/config/AdvisorConfig.java: public record AdvisorConfig(String provider, int topNForLlm)
```

`cmd/build.gradle.kts` already declares `implementation` dependencies on every module above, `implementation("info.picocli:picocli:$picocliVersion")`, `runtimeOnly("org.slf4j:slf4j-simple:...")`, and fixes `application.mainClass.set("dev.reachlayer.cli.Main")`. No build file changes are needed in this plan.

Test fixtures already on disk, used in Task 3:
- `fixtures/sample-fpr/audit.fvdl` — parses to exactly 2 SAST findings (verified via `connectors/fortify`'s own `FortifyConnectorTest`).
- `fixtures/sample-bdio/scan.json` — parses to exactly 3 SCA findings with CVEs `CVE-2021-44228`, `CVE-2021-35516`, `CVE-2019-12384` (verified via `connectors/blackduck`'s own `BlackDuckConnectorTest`).

---

### Task 1: `EnrichmentPipeline` — compose EPSS + KEV + blast-radius into one `EnrichmentStage`

**Files:**
- Create: `cmd/src/main/java/dev/reachlayer/cli/EnrichmentPipeline.java`
- Test: `cmd/src/test/java/dev/reachlayer/cli/EnrichmentPipelineTest.java`

**Interfaces:**
- Consumes: `dev.reachlayer.enrich.epss.EpssClient#lookup(List<String>)`, `dev.reachlayer.enrich.kev.KevClient#isKnownExploited(String)`, `dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer#analyze(Finding)`, `Finding#cve()`/`#toBuilder()`.
- Produces: `public final class EnrichmentPipeline implements EnrichmentStage` with constructor `EnrichmentPipeline(EpssClient epssClient, KevClient kevClient, BlastRadiusAnalyzer blastRadiusAnalyzer)` and `List<Finding> enrich(List<Finding> findings)`. Task 2 (`Main`) constructs and uses this directly.

- [ ] **Step 1: Write the failing test**

Create `cmd/src/test/java/dev/reachlayer/cli/EnrichmentPipelineTest.java`:

```java
package dev.reachlayer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer;
import dev.reachlayer.enrich.epss.EpssClient;
import dev.reachlayer.enrich.kev.KevClient;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EnrichmentPipelineTest {

    private static final String EPSS_RESPONSE =
            """
            {
              "status": "OK",
              "data": [
                { "cve": "CVE-2021-44228", "epss": "0.974730000", "percentile": "0.999720000", "date": "2024-01-01" },
                { "cve": "CVE-2021-35516", "epss": "0.012340000", "percentile": "0.500000000", "date": "2024-01-01" }
              ]
            }
            """;

    private static final String KEV_RESPONSE =
            """
            {
              "catalogVersion": "2024.06.01",
              "dateReleased": "2024-06-01T00:00:00.000Z",
              "count": 1,
              "vulnerabilities": [
                { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j" }
              ]
            }
            """;

    @TempDir
    Path tempDir;

    private Finding findingWithCve(String id, String cve) {
        return Finding.builder()
                .id(id)
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(Component.of("some-lib", "1.0.0"))
                .cve(cve == null ? List.of() : List.of(cve))
                .build();
    }

    @Test
    void batchesEpssLookupAcrossAllFindingsInOneFetch() {
        AtomicInteger epssFetchCount = new AtomicInteger();
        EpssClient epssClient = new EpssClient(
                uri -> {
                    epssFetchCount.incrementAndGet();
                    return EPSS_RESPONSE;
                },
                tempDir,
                () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        List<Finding> findings = List.of(
                findingWithCve("f1", "CVE-2021-44228"), findingWithCve("f2", "CVE-2021-35516"));

        List<Finding> enriched = pipeline.enrich(findings);

        assertThat(epssFetchCount.get()).isEqualTo(1);
        Epss f1Epss = enriched.get(0).epss();
        assertThat(f1Epss).isNotNull();
        assertThat(f1Epss.score()).isEqualTo(0.97473);
        Epss f2Epss = enriched.get(1).epss();
        assertThat(f2Epss).isNotNull();
        assertThat(f2Epss.percentile()).isEqualTo(0.5);
    }

    @Test
    void attachesKevFlagOnlyForKnownExploitedCve() {
        EpssClient epssClient = new EpssClient(uri -> EPSS_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        List<Finding> findings = List.of(
                findingWithCve("f1", "CVE-2021-44228"), findingWithCve("f2", "CVE-2021-35516"));

        List<Finding> enriched = pipeline.enrich(findings);

        assertThat(enriched.get(0).kev()).isTrue();
        assertThat(enriched.get(1).kev()).isFalse();
    }

    @Test
    void findingWithNoCveGetsNullEpssAndFalseKevButStillGetsBlastRadius() {
        EpssClient epssClient = new EpssClient(
                uri -> {
                    throw new AssertionError("EPSS should never be fetched when no finding has a CVE");
                },
                tempDir,
                () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        Finding noCve = Finding.builder().id("f1").source("fortify").kind(FindingKind.SAST).build();

        List<Finding> enriched = pipeline.enrich(List.of(noCve));

        assertThat(enriched.get(0).epss()).isNull();
        assertThat(enriched.get(0).kev()).isFalse();
        assertThat(enriched.get(0).blastRadius()).isNotNull();
    }

    @Test
    void doesNotMutateInputAndPreservesOrder() {
        EpssClient epssClient = new EpssClient(uri -> EPSS_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        KevClient kevClient = new KevClient(uri -> KEV_RESPONSE, tempDir, () -> LocalDate.of(2024, 6, 1));
        EnrichmentPipeline pipeline = new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());

        Finding original = findingWithCve("f1", "CVE-2021-44228");
        List<Finding> enriched = pipeline.enrich(List.of(original));

        assertThat(original.epss()).isNull(); // input untouched
        assertThat(enriched).hasSize(1);
        assertThat(enriched.get(0).id()).isEqualTo("f1");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew.bat :cmd:compileTestJava` (from repo root, with `JAVA_HOME` pointed at a JDK 21 install)
Expected: FAIL — compile error, `EnrichmentPipeline` does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `cmd/src/main/java/dev/reachlayer/cli/EnrichmentPipeline.java`:

```java
package dev.reachlayer.cli;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer;
import dev.reachlayer.enrich.epss.EpssClient;
import dev.reachlayer.enrich.kev.KevClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Composes the three independent {@code enrich} clients ({@link EpssClient}, {@link KevClient},
 * {@link BlastRadiusAnalyzer}) into a single {@link EnrichmentStage}. No {@code enrich}
 * submodule depends on the others, and none of them implement {@code EnrichmentStage} directly
 * — {@code cmd} is the only module that depends on all three, so the composition lives here.
 *
 * <p>EPSS lookups are batched: every distinct primary CVE across the whole input list is looked
 * up in a single {@link EpssClient#lookup(List)} call, rather than one HTTP round trip per
 * finding.
 */
public final class EnrichmentPipeline implements EnrichmentStage {

    private final EpssClient epssClient;
    private final KevClient kevClient;
    private final BlastRadiusAnalyzer blastRadiusAnalyzer;

    public EnrichmentPipeline(EpssClient epssClient, KevClient kevClient, BlastRadiusAnalyzer blastRadiusAnalyzer) {
        this.epssClient = Objects.requireNonNull(epssClient, "epssClient");
        this.kevClient = Objects.requireNonNull(kevClient, "kevClient");
        this.blastRadiusAnalyzer = Objects.requireNonNull(blastRadiusAnalyzer, "blastRadiusAnalyzer");
    }

    @Override
    public List<Finding> enrich(List<Finding> findings) {
        List<String> cveIds = findings.stream()
                .map(EnrichmentPipeline::primaryCve)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        Map<String, Epss> epssByCve = epssClient.lookup(cveIds);

        List<Finding> result = new ArrayList<>(findings.size());
        for (Finding finding : findings) {
            String cve = primaryCve(finding);
            Epss epss = cve == null ? null : epssByCve.get(cve);
            boolean kev = kevClient.isKnownExploited(cve);
            BlastRadius blastRadius = blastRadiusAnalyzer.analyze(finding);
            result.add(finding.toBuilder().epss(epss).kev(kev).blastRadius(blastRadius).build());
        }
        return result;
    }

    private static String primaryCve(Finding finding) {
        List<String> cve = finding.cve();
        return cve.isEmpty() ? null : cve.get(0);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew.bat :cmd:test --tests "dev.reachlayer.cli.EnrichmentPipelineTest"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add cmd/src/main/java/dev/reachlayer/cli/EnrichmentPipeline.java cmd/src/test/java/dev/reachlayer/cli/EnrichmentPipelineTest.java
git commit -m "feat(cmd): add EnrichmentPipeline composing EPSS/KEV/blast-radius"
```

---

### Task 2: `Main` — picocli CLI wiring every stage into `Orchestrator`

**Files:**
- Create: `cmd/src/main/java/dev/reachlayer/cli/Main.java`

**Interfaces:**
- Consumes: `EnrichmentPipeline` from Task 1; every class/signature listed in "Reference: exact signatures" above.
- Produces (package-private, used directly by Task 3's test — this is what makes `Main` testable without picocli or real network I/O):
  - `static ReachabilityStage buildReachabilityStage(String classesDir)`
  - `static EnrichmentStage buildEnrichmentStage(dev.reachlayer.enrich.epss.HttpFetcher epssFetcher, dev.reachlayer.enrich.kev.HttpFetcher kevFetcher, Path cacheDir)`
  - `static LlmProvider buildProvider(String providerName)`
  - `static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment)`
  - `static String firstNonBlank(String preferred, String fallback)`
  - Public entry point: `public static void main(String[] args)`.

- [ ] **Step 1: Write `Main.java`**

There is no unit test in this task — `Main`'s package-private static methods are exercised directly by Task 3's `MainWiringIT`, which is the "failing test first" for this task. Write `Main` now; Task 3 proves it.

Create `cmd/src/main/java/dev/reachlayer/cli/Main.java`:

```java
package dev.reachlayer.cli;

import dev.reachlayer.advisor.api.FixAdvisorService;
import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.advisor.providers.anthropic.AnthropicLlmProvider;
import dev.reachlayer.advisor.providers.noop.NoopLlmProvider;
import dev.reachlayer.connectors.blackduck.BlackDuckConnector;
import dev.reachlayer.connectors.fortify.FortifyConnector;
import dev.reachlayer.core.config.ConfigLoader;
import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.pipeline.ScoringStage;
import dev.reachlayer.core.spi.LlmProvider;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import dev.reachlayer.enrich.blastradius.BlastRadiusAnalyzer;
import dev.reachlayer.enrich.epss.EpssClient;
import dev.reachlayer.enrich.kev.KevClient;
import dev.reachlayer.output.api.ConsoleOutputRenderer;
import dev.reachlayer.output.githubpr.GitHubPrCommentRenderer;
import dev.reachlayer.output.githubpr.GitHubRestApiClient;
import dev.reachlayer.reach.ReachabilityTagger;
import dev.reachlayer.reach.signatures.ComponentLevelSignatureSource;
import dev.reachlayer.scoring.RiskScorer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Reachlayer's standalone CLI entry point (PLAN.md §10 step 6). Wires every already-implemented
 * pipeline module through {@link Orchestrator}. Per PLAN.md principle 1 ("never fail or block
 * the build"), any failure while actually running the pipeline is logged and swallowed — this
 * process always exits {@code 0} once argument parsing succeeds. A malformed CLI invocation
 * itself (before {@link #call()} runs) still gets picocli's normal non-zero exit; that is a
 * usage error, not a pipeline failure.
 */
@Command(name = "reachlayer", version = "reachlayer 0.1.0-SNAPSHOT", mixinStandardHelpOptions = true)
public final class Main implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    @Option(names = "--fortify", defaultValue = "", description = "Path to a Fortify audit.fvdl or .fpr export.")
    private String fortify;

    @Option(names = "--blackduck", defaultValue = "", description = "Path to a Black Duck JSON/BDIO export.")
    private String blackduck;

    @Option(names = "--repo", defaultValue = ".", description = "Path to the checked-out repository.")
    private String repo;

    @Option(names = "--classes", defaultValue = "", description = "Path to compiled application .class files.")
    private String classes;

    @Option(names = "--config", defaultValue = "", description = "Path to a reachlayer.yml config file.")
    private String config;

    @Option(names = "--out", defaultValue = "", description = "Path to also write the rendered Markdown report to.")
    private String out;

    @Option(names = "--cache-dir", defaultValue = ".reachlayer/cache", description = "EPSS/KEV disk cache directory.")
    private String cacheDir;

    @Option(
            names = "--post-pr-comment",
            defaultValue = "true",
            arity = "1",
            description = "Whether to upsert a PR comment via the GitHub REST API.")
    private boolean postPrComment;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        try {
            runPipeline();
        } catch (Exception e) {
            log.error("Reachlayer pipeline failed; not failing the build: {}", e.toString(), e);
        }
        return 0;
    }

    private void runPipeline() throws IOException {
        Path repoPath = Path.of(repo);
        ReachlayerConfig cfg = config.isBlank() ? ConfigLoader.loadDefaults() : ConfigLoader.load(Path.of(config));

        List<ScanSource> sources = new ArrayList<>();
        if (!fortify.isBlank()) {
            sources.add(ScanSource.ofPath(Path.of(fortify)));
        }
        if (!blackduck.isBlank()) {
            sources.add(ScanSource.ofPath(Path.of(blackduck)));
        }

        List<ScannerConnector> connectors = List.of(new FortifyConnector(), new BlackDuckConnector());
        ReachabilityStage reachabilityStage = buildReachabilityStage(classes);
        EnrichmentStage enrichmentStage = buildEnrichmentStage(
                new dev.reachlayer.enrich.epss.JdkHttpFetcher(),
                new dev.reachlayer.enrich.kev.JdkHttpFetcher(),
                Path.of(cacheDir));
        ScoringStage scoringStage = findings -> new RiskScorer().score(findings, cfg.scoring());
        LlmProvider provider = buildProvider(cfg.advisor().provider());
        AdvisorStage advisorStage = new FixAdvisorService(provider, cfg.advisor(), new ContextBuilder(), repoPath);
        List<OutputRenderer> outputRenderers =
                buildOutputRenderers(out.isBlank() ? null : Path.of(out), postPrComment);

        String repoLabel = firstNonBlank(System.getenv("GITHUB_REPOSITORY"), repo);

        Orchestrator orchestrator = new Orchestrator(
                connectors, reachabilityStage, enrichmentStage, scoringStage, advisorStage, outputRenderers, cfg);
        orchestrator.run(sources, repoLabel);
    }

    static ReachabilityStage buildReachabilityStage(String classesDir) {
        if (classesDir == null || classesDir.isBlank()) {
            return findings -> findings;
        }
        return new ReachabilityTagger(Path.of(classesDir), List.of(new ComponentLevelSignatureSource()));
    }

    static EnrichmentStage buildEnrichmentStage(
            dev.reachlayer.enrich.epss.HttpFetcher epssFetcher,
            dev.reachlayer.enrich.kev.HttpFetcher kevFetcher,
            Path cacheDir) {
        EpssClient epssClient = new EpssClient(epssFetcher, cacheDir);
        KevClient kevClient = new KevClient(kevFetcher, cacheDir);
        return new EnrichmentPipeline(epssClient, kevClient, new BlastRadiusAnalyzer());
    }

    static LlmProvider buildProvider(String providerName) {
        return "anthropic".equalsIgnoreCase(providerName) ? AnthropicLlmProvider.fromEnvironment() : new NoopLlmProvider();
    }

    static List<OutputRenderer> buildOutputRenderers(Path outFile, boolean attemptPrComment) {
        List<OutputRenderer> renderers = new ArrayList<>();
        renderers.add(new ConsoleOutputRenderer(System.out, outFile));
        if (attemptPrComment) {
            try {
                renderers.add(GitHubPrCommentRenderer.fromEnvironment(GitHubRestApiClient.fromEnvironment()));
            } catch (IllegalStateException e) {
                log.info("Skipping GitHub PR comment rendering: {}", e.getMessage());
            }
        }
        return renderers;
    }

    static String firstNonBlank(String preferred, String fallback) {
        return (preferred != null && !preferred.isBlank()) ? preferred : fallback;
    }
}
```

- [ ] **Step 2: Compile it**

Run: `./gradlew.bat :cmd:compileJava`
Expected: BUILD SUCCESSFUL. If it fails, the error will name a missing/mismatched symbol — cross-check against the "Reference: exact signatures" section above and the actual file in this repo before guessing a fix.

- [ ] **Step 3: Commit**

```bash
git add cmd/src/main/java/dev/reachlayer/cli/Main.java
git commit -m "feat(cmd): add Main picocli CLI wiring the full pipeline"
```

---

### Task 3: `MainWiringIT` — end-to-end wiring test against the real fixtures

**Files:**
- Test: `cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java`

**Interfaces:**
- Consumes: `Main`'s package-private static methods from Task 2, `Orchestrator` from `core`, `fixtures/sample-fpr/audit.fvdl` and `fixtures/sample-bdio/scan.json` (referenced by relative path from the repo root — see step 1 for exactly how the path is resolved from a test running under `cmd/`).

- [ ] **Step 1: Write the failing test**

Create `cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java`:

```java
package dev.reachlayer.cli;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.config.ReachlayerConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.pipeline.AdvisorStage;
import dev.reachlayer.core.pipeline.EnrichmentStage;
import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.pipeline.ScoringStage;
import dev.reachlayer.core.spi.LlmProvider;
import dev.reachlayer.core.spi.OutputRenderer;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import dev.reachlayer.advisor.api.FixAdvisorService;
import dev.reachlayer.advisor.api.retrieval.ContextBuilder;
import dev.reachlayer.connectors.blackduck.BlackDuckConnector;
import dev.reachlayer.connectors.fortify.FortifyConnector;
import dev.reachlayer.scoring.RiskScorer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises {@link Main}'s package-private wiring methods against the real
 * {@code fixtures/sample-fpr} and {@code fixtures/sample-bdio} exports, with fake
 * {@code HttpFetcher}s standing in for live EPSS/KEV network calls (never touch the network
 * from an automated test — same rule every other module's tests already follow). This proves
 * the wiring in {@link Main} actually produces a full, scored, rendered report end-to-end;
 * {@code Main.main(String[])} itself is not invoked here (that would require a real process
 * exit), but every piece it assembles is exercised through the exact same package-private
 * factory methods {@code Main.call()} calls.
 */
class MainWiringIT {

    /**
     * The repo root, resolved relative to this module's own source tree — {@code cmd}'s Gradle
     * project directory is {@code <repoRoot>/cmd}, so the parent directory is the repo root
     * where {@code fixtures/} lives.
     */
    private Path repoRoot() {
        return Path.of("").toAbsolutePath().getParent();
    }

    @Test
    void runsFullPipelineAgainstRealFixturesAndProducesAScoredRenderedReport(@TempDir Path tempDir) throws IOException {
        Path fortifyExport = repoRoot().resolve("fixtures/sample-fpr/audit.fvdl");
        Path blackduckExport = repoRoot().resolve("fixtures/sample-bdio/scan.json");
        assertThat(fortifyExport).exists();
        assertThat(blackduckExport).exists();

        List<ScanSource> sources =
                List.of(ScanSource.ofPath(fortifyExport), ScanSource.ofPath(blackduckExport));
        List<ScannerConnector> connectors = List.of(new FortifyConnector(), new BlackDuckConnector());

        ReachabilityStage reachabilityStage = Main.buildReachabilityStage(""); // no classes dir: identity passthrough
        EnrichmentStage enrichmentStage = Main.buildEnrichmentStage(
                uri -> "{\"status\":\"OK\",\"data\":[]}", // fake EPSS fetcher: no data, never throws
                uri -> "{\"vulnerabilities\":[]}", // fake KEV fetcher: empty catalog, never throws
                tempDir.resolve("cache"));
        ScoringStage scoringStage = findings -> new RiskScorer().score(findings, ReachlayerConfig.defaults().scoring());
        LlmProvider provider = Main.buildProvider("noop");
        AdvisorStage advisorStage =
                new FixAdvisorService(provider, ReachlayerConfig.defaults().advisor(), new ContextBuilder(), repoRoot());

        Path outFile = tempDir.resolve("report.md");
        List<OutputRenderer> outputRenderers = Main.buildOutputRenderers(outFile, false); // no GitHub env vars in CI

        Orchestrator orchestrator = new Orchestrator(
                connectors,
                reachabilityStage,
                enrichmentStage,
                scoringStage,
                advisorStage,
                outputRenderers,
                ReachlayerConfig.defaults());

        RankedReport report = orchestrator.run(sources, "reachlayer/reachlayer");

        assertThat(report.findings()).hasSize(5); // 2 SAST from Fortify + 3 SCA from Black Duck
        assertThat(report.findings()).allSatisfy(f -> {
            assertThat(f.riskScore()).isNotNull();
            assertThat(f.riskExplanation()).isNotNull();
            assertThat(f.fixSuggestion()).isNotNull();
            assertThat(f.reachability()).isNotNull(); // UNKNOWN, since no --classes was given
        });

        List<String> allCves = new ArrayList<>();
        report.findings().forEach(f -> allCves.addAll(f.cve()));
        assertThat(allCves)
                .containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2021-35516", "CVE-2019-12384");

        assertThat(outFile).exists();
        String written = Files.readString(outFile);
        assertThat(written).contains("reachlayer:report"); // the default comment marker
        assertThat(written).contains("reachlayer/reachlayer");
    }

    @Test
    void classesDirEmptyMeansIdentityReachabilityStage() {
        ReachabilityStage stage = Main.buildReachabilityStage("");
        Finding input = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(dev.reachlayer.core.model.FindingKind.SAST)
                .build();

        List<Finding> result = stage.tag == null ? null : null; // placeholder removed below
        List<Finding> tagged = stage.tag(List.of(input));

        assertThat(tagged).containsExactly(input); // identity: same reference, unchanged
    }

    @Test
    void buildProviderSelectsAnthropicOnlyWhenConfigured() {
        assertThat(Main.buildProvider("noop")).isInstanceOf(dev.reachlayer.advisor.providers.noop.NoopLlmProvider.class);
        assertThat(Main.buildProvider("anything-else"))
                .isInstanceOf(dev.reachlayer.advisor.providers.noop.NoopLlmProvider.class);
        assertThat(Main.buildProvider("anthropic"))
                .isInstanceOf(dev.reachlayer.advisor.providers.anthropic.AnthropicLlmProvider.class);
    }

    @Test
    void firstNonBlankPrefersPreferredValue() {
        assertThat(Main.firstNonBlank("a", "b")).isEqualTo("a");
        assertThat(Main.firstNonBlank("", "b")).isEqualTo("b");
        assertThat(Main.firstNonBlank(null, "b")).isEqualTo("b");
    }
}
```

Note the `classesDirEmptyMeansIdentityReachabilityStage` test above has a stray placeholder line (`List<Finding> result = stage.tag == null ? null : null;`) that must be deleted before running — remove it in Step 1 itself; it is left in this plan only to make an editing mistake visible if copy-pasted verbatim. The corrected test body is:

```java
    @Test
    void classesDirEmptyMeansIdentityReachabilityStage() {
        ReachabilityStage stage = Main.buildReachabilityStage("");
        Finding input = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(dev.reachlayer.core.model.FindingKind.SAST)
                .build();

        List<Finding> tagged = stage.tag(List.of(input));

        assertThat(tagged).containsExactly(input); // identity: same reference, unchanged
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew.bat :cmd:test --tests "dev.reachlayer.cli.MainWiringIT"`
Expected: FAIL to compile if Task 2's `Main` is missing any of the four package-private methods this test calls, or FAIL an assertion if the wiring is wrong (e.g. wrong finding count, missing marker text). If `Main.java` from Task 2 was written correctly, this may in fact pass on the first run — that is fine; the "write test first" step still matters because it is what proves Task 2's wiring, and a passing run on first try is only valid if you first temporarily break one piece (e.g. change `hasSize(5)` to `hasSize(999)`) and confirm the test fails, to rule out a vacuously-true assertion. Do that check now, then revert.

- [ ] **Step 3: Fix any wiring bugs surfaced**

If the test fails, the failure will point at one of: a wrong constructor argument order, a missing import, or an incorrect assumption about finding counts/CVE ids. Cross-check against `FortifyConnectorTest`/`BlackDuckConnectorTest` (already read during planning — 2 SAST + 3 SCA findings, CVEs `CVE-2021-44228`/`CVE-2021-35516`/`CVE-2019-12384`) and the "Reference: exact signatures" section at the top of this plan before changing anything speculatively.

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew.bat :cmd:test --tests "dev.reachlayer.cli.MainWiringIT"`
Expected: PASS, 4 tests.

- [ ] **Step 5: Run the full three-module-plus-cmd test suite**

Run: `./gradlew.bat :cmd:test`
Expected: BUILD SUCCESSFUL, `EnrichmentPipelineTest` (4 tests) + `MainWiringIT` (4 tests) all pass.

- [ ] **Step 6: Commit**

```bash
git add cmd/src/test/java/dev/reachlayer/cli/MainWiringIT.java
git commit -m "test(cmd): add end-to-end wiring test against real fixtures"
```

---

### Task 4: Full build verification and one manual end-to-end run

**Files:** none created; this task runs the built artifact, it does not add code.

**Interfaces:** none new — this task is a verification pass over Tasks 1–3's output.

- [ ] **Step 1: Run the full repo build**

Run: `./gradlew.bat build` (from repo root)
Expected: BUILD SUCCESSFUL — every module's tests pass, including `cmd`'s new ones, and `:cmd:shadowJar` runs as part of `build` (per `cmd/build.gradle.kts`'s `tasks.named("build") { dependsOn(tasks.named("shadowJar")) }`).

- [ ] **Step 2: Confirm the fat jar exists**

Run: `ls cmd/build/libs/cmd-all.jar` (or `dir` on Windows)
Expected: the file exists — this is exactly the artifact `README.md`'s Quickstart and `action.yml`'s Dockerfile expect.

- [ ] **Step 3: Run the CLI once against the real fixtures, exactly as README.md's Quickstart documents**

Run (from repo root):

```bash
java -jar cmd/build/libs/cmd-all.jar \
  --fortify fixtures/sample-fpr/audit.fvdl \
  --blackduck fixtures/sample-bdio/scan.json \
  --repo . \
  --out reachlayer-report.md
```

Expected: exits `0`; prints a Markdown report to stdout beginning with `<!-- reachlayer:report -->`; `reachlayer-report.md` is created in the repo root with the same content. No `GITHUB_TOKEN`/`GITHUB_REPOSITORY`/`GITHUB_PR_NUMBER` env vars are set for this run, so the GitHub PR renderer is skipped with a logged `INFO` line (not an error) — confirm that log line appears and the process still exits `0`.

- [ ] **Step 4: Inspect the generated report**

Run: `cat reachlayer-report.md` (or open it)
Expected: contains a "Top N" Markdown table with 5 rows total (or fewer visible + a collapsible "Show all" section, depending on `OutputConfig.defaults().topN()` which is 5 — so all 5 will be in the visible top table), each row showing a risk score, severity, reachability (`unknown`, since `--classes` was not passed), the three Black Duck CVE ids, and a fix suggestion (templated, since no `ANTHROPIC_API_KEY` was set).

- [ ] **Step 5: Clean up the manual run's output file**

Run: `rm reachlayer-report.md` (it is a manual verification artifact, not a repo file — do not commit it)

- [ ] **Step 6: Update README's "Status" section**

**File:** Modify `README.md` — replace the `## Status` section's first paragraph.

Current text:

```markdown
## Status

This is an MVP skeleton (Phase 0 of `PLAN.md` §5). Reachability uses CHA/RTA-style
call-graph approximation and component-level signatures; blast-radius and entry-point discovery
are intentionally simple, conservative heuristics that lean toward `unknown` rather than claiming
certainty. See `docs/reachability-caveats.md`.
```

New text:

```markdown
## Status

The full pipeline — connectors → reachability → enrich → scoring → advisor → output — is wired
end-to-end via `cmd`'s `Main` CLI and runnable today (see Quickstart above). Reachability uses
CHA/RTA-style call-graph approximation and component-level signatures; blast-radius and
entry-point discovery are intentionally simple, conservative heuristics that lean toward
`unknown` rather than claiming certainty. See `docs/reachability-caveats.md`.
```

- [ ] **Step 7: Commit the README update**

```bash
git add README.md
git commit -m "docs: update Status section now that cmd's CLI wires the full pipeline"
```

---

## Self-review notes (completed during planning, not a task to execute)

- **Spec coverage:** every section of the design spec (`docs/superpowers/specs/2026-07-02-cmd-cli-orchestrator-wiring-design.md`) maps to a task: CLI contract → Task 2, `EnrichmentPipeline` → Task 1, wiring decisions (provider selection, reachability passthrough, GitHub renderer conditional) → Task 2, testing → Tasks 1 and 3, manual end-to-end proof → Task 4.
- **Placeholder scan:** none of the "No Placeholders" red-flag patterns appear in the task bodies above; the one intentionally-flagged stray line in Task 3 is explicitly called out and corrected inline, not left as an ambiguous TODO.
- **Type consistency:** `EnrichmentPipeline`'s constructor signature in Task 1 exactly matches its use in `Main.buildEnrichmentStage` in Task 2, which exactly matches its use in `MainWiringIT` in Task 3. `ReachabilityStage`/`EnrichmentStage`/`ScoringStage`/`AdvisorStage` are used consistently as `@FunctionalInterface` types across all three tasks.
