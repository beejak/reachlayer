package dev.reachlayer.core.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Writes a {@link PipelineMetrics} snapshot to disk as JSON, mirroring {@code
 * core.baseline.BaselineStore}'s never-throws local-file-I/O convention: a write failure (e.g. an
 * unwritable directory) logs a warning and otherwise does nothing — metrics are a side artifact of
 * a run, never something the run's own success depends on, per PLAN.md principle 1.
 *
 * <p>Unlike {@code BaselineStore} (which deliberately avoids Jackson's {@code jsr310} module by
 * keeping its on-disk timestamp a plain {@code String}), {@link PipelineMetrics}'s {@code Instant}
 * fields are serialized directly: this class registers {@link JavaTimeModule} on its own {@link
 * ObjectMapper} and disables {@code WRITE_DATES_AS_TIMESTAMPS} so instants render as ISO-8601
 * strings, not epoch-second arrays.
 */
public final class MetricsWriter {

    private static final Logger log = LoggerFactory.getLogger(MetricsWriter.class);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private MetricsWriter() {
    }

    /** No-op if {@code path} is {@code null}. Never throws. */
    public static void write(Path path, PipelineMetrics metrics) {
        if (path == null) {
            return;
        }
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(metrics);
            Files.writeString(path, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Could not write pipeline metrics to {} ({}); continuing without persisting", path, e.getMessage());
        }
    }
}
