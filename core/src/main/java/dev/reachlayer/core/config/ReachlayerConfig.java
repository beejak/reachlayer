package dev.reachlayer.core.config;

/** Root configuration object loaded from {@code reachlayer.yml} (or defaults if absent). */
public record ReachlayerConfig(
        ScoringWeights scoring, AdvisorConfig advisor, OutputConfig output, EntryPointOverrides entryPoints) {

    public static ReachlayerConfig defaults() {
        return new ReachlayerConfig(
                ScoringWeights.defaults(), AdvisorConfig.defaults(), OutputConfig.defaults(),
                EntryPointOverrides.defaults());
    }
}
