package dev.reachlayer.core.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetricsWriterTest {

    private static PipelineMetrics sampleMetrics() {
        return new PipelineMetrics(
                Instant.parse("2026-07-31T12:00:00Z"),
                Instant.parse("2026-07-31T12:00:01Z"),
                1000L,
                2,
                5,
                Map.of("scoring", 10L),
                Map.of(),
                Map.of("high", 2),
                Map.of("fortify", 3),
                Map.of("unknown", 5),
                1,
                0,
                Map.of());
    }

    @Test
    void writesValidJsonToGivenPath(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("metrics.json");

        MetricsWriter.write(file, sampleMetrics());

        assertThat(file).exists();
        String raw = Files.readString(file);
        assertThat(raw).contains("\"totalDurationMs\" : 1000");
        assertThat(raw).contains("\"findingsIngested\" : 5");
        assertThat(raw).contains("\"scoring\" : 10");
    }

    @Test
    void createsMissingParentDirectories(@TempDir Path tempDir) {
        Path file = tempDir.resolve("nested/dir/metrics.json");

        MetricsWriter.write(file, sampleMetrics());

        assertThat(file).exists();
    }

    @Test
    void isNoOpAndNeverThrowsWhenPathIsNull() {
        assertThatCode(() -> MetricsWriter.write(null, sampleMetrics())).doesNotThrowAnyException();
    }
}
