package dev.reachlayer.fixtures.corpusgen;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Standalone CLI entry point for {@link CorpusGenerator}, used by the evaluation pipeline (see
 * {@code docs/evaluation-pipeline.md}) to produce a fresh synthetic corpus outside of a test run
 * -- e.g. from a shell script or CI step, without spinning up a JVM test harness.
 *
 * <p>Usage: {@code java -cp ... dev.reachlayer.fixtures.corpusgen.Main <outputDir> [seed]
 * [extraSastCount] [extraScaCount]}
 */
public final class Main {

    private static final long DEFAULT_SEED = 42L;
    private static final int DEFAULT_EXTRA_SAST = 40;
    private static final int DEFAULT_EXTRA_SCA = 60;

    private Main() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println(
                    "Usage: Main <outputDir> [seed=" + DEFAULT_SEED + "] [extraSastCount=" + DEFAULT_EXTRA_SAST
                            + "] [extraScaCount=" + DEFAULT_EXTRA_SCA + "]");
            System.exit(2);
            return;
        }

        Path outputDir = Path.of(args[0]);
        long seed = args.length > 1 ? Long.parseLong(args[1]) : DEFAULT_SEED;
        int extraSastCount = args.length > 2 ? Integer.parseInt(args[2]) : DEFAULT_EXTRA_SAST;
        int extraScaCount = args.length > 3 ? Integer.parseInt(args[3]) : DEFAULT_EXTRA_SCA;

        GeneratedCorpus corpus = CorpusGenerator.generate(seed, extraSastCount, extraScaCount);

        Files.createDirectories(outputDir);
        Path fvdl = outputDir.resolve("audit.fvdl");
        Path scan = outputDir.resolve("scan.json");
        Files.writeString(fvdl, corpus.fvdlXml(), StandardCharsets.UTF_8);
        Files.writeString(scan, corpus.blackDuckJson(), StandardCharsets.UTF_8);

        System.out.println("Generated " + corpus.sastFindingCount() + " SAST finding(s) -> " + fvdl);
        System.out.println("Generated " + corpus.scaFindingCount() + " SCA finding(s) -> " + scan);
    }
}
