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

    @Option(names = "--cache-dir", defaultValue = ".reachlayer-cache", description = "EPSS/KEV disk cache directory.")
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
