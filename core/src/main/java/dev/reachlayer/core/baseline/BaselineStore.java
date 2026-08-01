package dev.reachlayer.core.baseline;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads and writes the baseline JSON file used by "baseline/diff mode" (PLAN.md §5 Phase 1) to
 * round-trip a set of finding ids between two independent Reachlayer runs — typically a scheduled
 * scan of the base branch ({@code --baseline-out}) and a PR run that diffs against it ({@code
 * --baseline-in}). Pure local file I/O; unlike {@code enrich.epss}'s {@code EpssClient} / {@code
 * enrich.kev}'s {@code KevClient} (which inject a fake HTTP fetcher in tests), there is no network
 * boundary here to fake — tests exercise this class directly against a real {@code @TempDir Path}.
 *
 * <p>File shape:
 *
 * <pre>{@code
 * {
 *   "generatedAt": "2026-07-31T12:00:00Z",
 *   "findingIds": ["fortify-1a2b3c", "blackduck-4d5e6f"]
 * }
 * }</pre>
 *
 * <p>{@code generatedAt} is a plain ISO-8601 string (not a Jackson-typed {@code Instant}) —
 * mirrors {@code EpssClient}'s/{@code KevClient}'s own cache-file DTOs, which both store their
 * "last refreshed" timestamp as a plain {@code String}, avoiding any need to register Jackson's
 * {@code jackson-datatype-jsr310} module on this class's {@link ObjectMapper}.
 *
 * <p>Never throws: per PLAN.md principle 1 ("never fail or block the build"), a missing,
 * unreadable, or malformed baseline file degrades {@link #read(Path)} to {@code null} — the
 * caller's job is to treat that exactly like {@code --baseline-in} was never supplied — and a
 * failed {@link #write} logs a warning and otherwise does nothing; the baseline file is a side
 * artifact of a run, never something the run's own success depends on.
 */
public final class BaselineStore {

    private static final Logger log = LoggerFactory.getLogger(BaselineStore.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private BaselineStore() {
    }

    /**
     * Reads a baseline file previously written by {@link #write}. Returns {@code null} if {@code
     * path} is {@code null}, does not exist, or cannot be parsed — never throws.
     */
    public static Baseline read(Path path) {
        if (path == null || !Files.isRegularFile(path)) {
            return null;
        }
        try {
            String content = Files.readString(path, StandardCharsets.UTF_8);
            BaselineFile dto = MAPPER.readValue(content, BaselineFile.class);
            Instant generatedAt = parseInstant(dto.generatedAt());
            Set<String> findingIds = dto.findingIds() == null ? Set.of() : Set.copyOf(dto.findingIds());
            return new Baseline(generatedAt, findingIds);
        } catch (IOException | RuntimeException e) {
            log.warn("Could not read baseline file at {} ({}); proceeding without a baseline", path, e.getMessage());
            return null;
        }
    }

    /**
     * Writes {@code findingIds} as a baseline JSON file at {@code path}, for a future run to diff
     * against. No-op if {@code path} is {@code null}. Never throws: a write failure (e.g. an
     * unwritable directory) logs a warning; the current run is otherwise unaffected.
     */
    public static void write(Path path, Set<String> findingIds, Instant generatedAt) {
        if (path == null) {
            return;
        }
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Instant effectiveGeneratedAt = generatedAt == null ? Instant.now() : generatedAt;
            BaselineFile dto = new BaselineFile(
                    effectiveGeneratedAt.toString(), findingIds == null ? List.of() : List.copyOf(findingIds));
            String json = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(dto);
            Files.writeString(path, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Could not write baseline file at {} ({}); continuing without persisting", path, e.getMessage());
        }
    }

    private static Instant parseInstant(String s) {
        if (s == null) {
            return null;
        }
        try {
            return Instant.parse(s);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** Shape of the on-disk baseline file. */
    private record BaselineFile(String generatedAt, List<String> findingIds) {
    }
}
