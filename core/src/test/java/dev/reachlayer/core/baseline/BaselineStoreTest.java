package dev.reachlayer.core.baseline;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BaselineStoreTest {

    @Test
    void writeThenReadRoundTrips(@TempDir Path tempDir) {
        Path file = tempDir.resolve("baseline.json");
        Instant generatedAt = Instant.parse("2026-07-31T12:00:00Z");
        Set<String> ids = Set.of("fortify-1a2b3c", "blackduck-4d5e6f");

        BaselineStore.write(file, ids, generatedAt);
        Baseline baseline = BaselineStore.read(file);

        assertThat(baseline).isNotNull();
        assertThat(baseline.generatedAt()).isEqualTo(generatedAt);
        assertThat(baseline.findingIds()).containsExactlyInAnyOrderElementsOf(ids);
    }

    @Test
    void writeCreatesMissingParentDirectories(@TempDir Path tempDir) {
        Path file = tempDir.resolve("nested/dir/baseline.json");

        BaselineStore.write(file, Set.of("f1"), Instant.now());

        assertThat(Files.exists(file)).isTrue();
    }

    @Test
    void readReturnsNullWhenFileMissing(@TempDir Path tempDir) {
        assertThat(BaselineStore.read(tempDir.resolve("does-not-exist.json"))).isNull();
    }

    @Test
    void readReturnsNullWhenPathIsNull() {
        assertThat(BaselineStore.read(null)).isNull();
    }

    @Test
    void readReturnsNullAndNeverThrowsOnMalformedJson(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.json");
        Files.writeString(file, "{ not valid json ]");

        assertThatCode(() -> BaselineStore.read(file)).doesNotThrowAnyException();
        assertThat(BaselineStore.read(file)).isNull();
    }

    @Test
    void writeIsNoOpAndNeverThrowsWhenPathIsNull() {
        assertThatCode(() -> BaselineStore.write(null, Set.of("f1"), Instant.now())).doesNotThrowAnyException();
    }

    @Test
    void writtenFileContainsExpectedJsonShape(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("baseline.json");

        BaselineStore.write(file, Set.of("fortify-1a2b3c"), Instant.parse("2026-07-31T12:00:00Z"));

        String raw = Files.readString(file);
        assertThat(raw).contains("\"generatedAt\"").contains("2026-07-31T12:00:00Z");
        assertThat(raw).contains("\"findingIds\"").contains("fortify-1a2b3c");
    }
}
