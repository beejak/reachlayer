package dev.reachlayer.output.api;

import dev.reachlayer.core.config.OutputConfig;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A tiny, always-safe {@link OutputRenderer} useful for the standalone CLI path: prints the
 * formatted Markdown report to a {@link PrintStream} (defaulting to {@link System#out}) and,
 * optionally, also writes it to a file.
 */
public final class ConsoleOutputRenderer implements OutputRenderer {

    private final PrintStream out;
    private final Path outputFile;
    private final MarkdownReportFormatter formatter;

    /** Prints to {@link System#out}; no file is written. */
    public ConsoleOutputRenderer() {
        this(System.out, null);
    }

    /** Prints to {@code out}; no file is written. */
    public ConsoleOutputRenderer(PrintStream out) {
        this(out, null);
    }

    /**
     * @param out stream to print the formatted report to (defaults to {@link System#out} if
     *     {@code null})
     * @param outputFile optional path to also write the Markdown report to; {@code null} to skip
     *     file output entirely
     */
    public ConsoleOutputRenderer(PrintStream out, Path outputFile) {
        this.out = out == null ? System.out : out;
        this.outputFile = outputFile;
        this.formatter = new MarkdownReportFormatter();
    }

    @Override
    public String name() {
        return "console";
    }

    @Override
    public void render(RankedReport report) throws OutputException {
        String markdown = formatter.format(report, OutputConfig.defaults().commentMarker());
        out.println(markdown);

        if (outputFile != null) {
            try {
                Path parent = outputFile.toAbsolutePath().getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
                Files.writeString(outputFile, markdown, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new OutputException("Failed to write report to " + outputFile, e);
            }
        }
    }
}
