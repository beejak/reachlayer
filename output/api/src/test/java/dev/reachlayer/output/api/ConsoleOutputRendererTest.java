package dev.reachlayer.output.api;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.config.OutputConfig;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.RankedReport;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConsoleOutputRendererTest {

    @Test
    void printsFormattedReportContainingMarkerToTheGivenStream() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        ConsoleOutputRenderer renderer = new ConsoleOutputRenderer(printStream);

        renderer.render(sampleReport());

        String printed = buffer.toString(StandardCharsets.UTF_8);
        assertThat(printed).contains(OutputConfig.defaults().commentMarker());
        assertThat(printed).contains("## Reachlayer risk triage");
        assertThat(renderer.name()).isEqualTo("console");
    }

    @Test
    void alsoWritesReportToFileWhenPathProvided(@TempDir Path tempDir) throws Exception {
        Path outputFile = tempDir.resolve("report.md");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        ConsoleOutputRenderer renderer = new ConsoleOutputRenderer(printStream, outputFile);

        renderer.render(sampleReport());

        assertThat(Files.exists(outputFile)).isTrue();
        String fileContent = Files.readString(outputFile, StandardCharsets.UTF_8);
        assertThat(fileContent).contains(OutputConfig.defaults().commentMarker());
        assertThat(fileContent).contains("## Reachlayer risk triage");
    }

    @Test
    void doesNotWriteFileWhenPathIsNull() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        ConsoleOutputRenderer renderer = new ConsoleOutputRenderer(printStream, null);

        renderer.render(sampleReport());

        assertThat(buffer.toString(StandardCharsets.UTF_8)).isNotBlank();
    }

    private static RankedReport sampleReport() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Sample finding")
                .severity("High")
                .riskScore(75.0)
                .build();
        return RankedReport.of(List.of(finding), "acme/widgets", 5);
    }
}
