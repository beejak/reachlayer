package dev.reachlayer.advisor.api.retrieval;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.spi.AdvisorContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ContextBuilderTest {

    private final ContextBuilder contextBuilder = new ContextBuilder();

    @Test
    void happyPathReadsSnippetAroundLineRange(@TempDir Path tempDir) throws IOException {
        Path repoRoot = tempDir;
        Path file = repoRoot.resolve("src/main/java/Foo.java");
        Files.createDirectories(file.getParent());
        List<String> lines = List.of(
                "line1", "line2", "line3", "line4 vulnerable start", "line5 vulnerable end", "line6", "line7",
                "line8");
        Files.write(file, lines);

        Location location = new Location("src/main/java/Foo.java", 4, 5, "Foo.bar()");
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("SQL Injection")
                .description("Untrusted input flows into a query.")
                .location(location)
                .build();

        AdvisorContext context = contextBuilder.buildContext(finding, repoRoot);

        assertThat(context.advisoryText()).isEqualTo("Untrusted input flows into a query.");
        assertThat(context.codeSnippet()).isNotNull();
        assertThat(context.codeSnippet()).contains("line4 vulnerable start");
        assertThat(context.codeSnippet()).contains("line5 vulnerable end");
        // padding should pull in a couple of surrounding lines too
        assertThat(context.codeSnippet()).contains("line1", "line7");
        assertThat(context.dependencyContext()).isNull();
    }

    @Test
    void missingFileDegradesToNullSnippetWithoutThrowing(@TempDir Path tempDir) {
        Location location = new Location("does/not/exist.java", 1, 2, null);
        Finding finding = Finding.builder()
                .id("f2")
                .source("fortify")
                .kind(FindingKind.SAST)
                .description("desc")
                .location(location)
                .build();

        AdvisorContext context = contextBuilder.buildContext(finding, tempDir);

        assertThat(context.codeSnippet()).isNull();
        assertThat(context.advisoryText()).isEqualTo("desc");
    }

    @Test
    void nullRepoRootSkipsSnippetRetrieval() {
        Location location = new Location("Foo.java", 1, 2, null);
        Finding finding = Finding.builder()
                .id("f3")
                .source("fortify")
                .kind(FindingKind.SAST)
                .description("desc")
                .location(location)
                .build();

        AdvisorContext context = contextBuilder.buildContext(finding, null);

        assertThat(context.codeSnippet()).isNull();
    }

    @Test
    void noComponentYieldsNullDependencyContext() {
        Finding finding = Finding.builder()
                .id("f4")
                .source("fortify")
                .kind(FindingKind.SAST)
                .description("desc")
                .build();

        AdvisorContext context = contextBuilder.buildContext(finding, null);

        assertThat(context.dependencyContext()).isNull();
    }

    @Test
    void componentAndCvesProduceDependencyContext() {
        Component component = Component.of("org.example:lib", "1.0.0");
        Finding finding = Finding.builder()
                .id("f5")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .component(component)
                .cve(List.of("CVE-2021-1234", "CVE-2022-5678"))
                .description("Vulnerable dependency")
                .build();

        AdvisorContext context = contextBuilder.buildContext(finding, null);

        assertThat(context.dependencyContext())
                .isEqualTo("org.example:lib@1.0.0 (CVEs: CVE-2021-1234,CVE-2022-5678)");
    }
}
