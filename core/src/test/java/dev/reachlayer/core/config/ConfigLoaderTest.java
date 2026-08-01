package dev.reachlayer.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ConfigLoaderTest {

    @Test
    void missingFileFallsBackToDefaults() throws Exception {
        ReachlayerConfig config = ConfigLoader.load(Path.of("does-not-exist.yml"));
        assertThat(config).isEqualTo(ReachlayerConfig.defaults());
    }

    @Test
    void nullPathFallsBackToDefaults() throws Exception {
        assertThat(ConfigLoader.load((Path) null)).isEqualTo(ReachlayerConfig.defaults());
    }

    @Test
    void loadsPartialOverridesAndFillsRestWithDefaults() {
        String yaml =
                """
                scoring:
                  unreachableMultiplier: 0.2
                advisor:
                  provider: anthropic
                output:
                  topN: 10
                """;
        ReachlayerConfig config = ConfigLoader.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.scoring().unreachableMultiplier()).isEqualTo(0.2);
        assertThat(config.scoring().cvssWeight()).isEqualTo(ScoringWeights.defaults().cvssWeight());
        assertThat(config.advisor().provider()).isEqualTo("anthropic");
        assertThat(config.advisor().topNForLlm()).isEqualTo(AdvisorConfig.defaults().topNForLlm());
        assertThat(config.output().topN()).isEqualTo(10);
    }

    @Test
    void emptyYamlFallsBackToDefaults() {
        ReachlayerConfig config =
                ConfigLoader.load(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)));
        assertThat(config).isEqualTo(ReachlayerConfig.defaults());
    }

    @Test
    void parsesEntryPointOverrides() {
        String yaml =
                """
                entryPoints:
                  extraAnnotations:
                    - "com.example.scheduling.Scheduled"
                    - "com.example.messaging.KafkaListener"
                  extraClasses:
                    - "com.example.jobs.NightlyReportJob"
                """;
        ReachlayerConfig config = ConfigLoader.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.entryPoints().extraAnnotations())
                .containsExactly("com.example.scheduling.Scheduled", "com.example.messaging.KafkaListener");
        assertThat(config.entryPoints().extraClasses()).containsExactly("com.example.jobs.NightlyReportJob");
    }

    @Test
    void missingEntryPointsSectionFallsBackToEmptyOverrides() {
        ReachlayerConfig config =
                ConfigLoader.load(new ByteArrayInputStream("scoring: {}".getBytes(StandardCharsets.UTF_8)));

        assertThat(config.entryPoints()).isEqualTo(EntryPointOverrides.defaults());
    }

    @Test
    void parsesSuppressionDisplayCwes() {
        String yaml =
                """
                suppression:
                  displayCwes:
                    "CWE-563": "Team decision: unused-variable warnings are pure lint noise here (JIRA-1234)"
                    "CWE-1004": "Not actionable in this codebase"
                """;
        ReachlayerConfig config = ConfigLoader.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.suppression().displayCwes())
                .containsEntry("CWE-563", "Team decision: unused-variable warnings are pure lint noise here (JIRA-1234)")
                .containsEntry("CWE-1004", "Not actionable in this codebase");
    }

    @Test
    void missingSuppressionSectionFallsBackToEmptyRules() {
        ReachlayerConfig config =
                ConfigLoader.load(new ByteArrayInputStream("scoring: {}".getBytes(StandardCharsets.UTF_8)));

        assertThat(config.suppression()).isEqualTo(SuppressionConfig.defaults());
    }

    @Test
    void nonStringSuppressionValuesAreDroppedRatherThanFailingToParse() {
        String yaml =
                """
                suppression:
                  displayCwes:
                    "CWE-563": 42
                """;
        ReachlayerConfig config = ConfigLoader.load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));

        assertThat(config.suppression().displayCwes()).isEmpty();
    }
}
