package dev.reachlayer.output.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SarifOutputRendererTest {

    private static RankedReport sampleReport() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Sample finding")
                .severity("High")
                .riskScore(80.0)
                .build();
        return RankedReport.of(List.of(finding), "acme/widgets", 5);
    }

    @Test
    void nameIsSarif() {
        SarifOutputRenderer renderer = new SarifOutputRenderer(Path.of("unused.sarif"));
        assertThat(renderer.name()).isEqualTo("sarif");
    }

    @Test
    void writesValidSarifJsonToGivenPath(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        renderer.render(sampleReport());

        assertThat(Files.exists(outputFile)).isTrue();
        JsonNode json = new ObjectMapper().readTree(Files.readString(outputFile));
        assertThat(json.at("/version").asText()).isEqualTo("2.1.0");
        assertThat(json.at("/runs/0/results/0/ruleId").asText()).isEqualTo("fortify:sample-finding");
    }

    @Test
    void createsParentDirectoriesIfMissing(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("nested/dir/report.sarif");
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        renderer.render(sampleReport());

        assertThat(Files.exists(outputFile)).isTrue();
    }

    @Test
    void omitsNullFieldsLikeRegionWhenLocationHasNoLineNumber(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        new SarifOutputRenderer(outputFile).render(sampleReport());

        String raw = Files.readString(outputFile);
        assertThat(raw).doesNotContain("\"region\" : null");
        assertThat(raw).doesNotContain("\"region\":null");
    }

    @Test
    void wrapsIoFailureAsOutputException(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.sarif");
        Files.createDirectory(outputFile); // a directory already occupies this path -> write must fail
        SarifOutputRenderer renderer = new SarifOutputRenderer(outputFile);

        assertThatThrownBy(() -> renderer.render(sampleReport()))
                .isInstanceOf(OutputException.class)
                .hasMessageContaining(outputFile.toString())
                .hasCauseInstanceOf(java.io.IOException.class);
    }
}
