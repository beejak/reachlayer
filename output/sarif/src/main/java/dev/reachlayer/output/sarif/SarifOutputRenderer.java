package dev.reachlayer.output.sarif;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.RankedReport;
import dev.reachlayer.core.spi.OutputException;
import dev.reachlayer.core.spi.OutputRenderer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Writes a {@link RankedReport} as a SARIF 2.1.0 JSON file to {@code outputFile}, for later
 * upload via a {@code github/codeql-action/upload-sarif} workflow step (Reachlayer itself never
 * calls GitHub's upload API — see {@code docs/sarif-output.md}). Mapping is delegated entirely to
 * {@link SarifReportBuilder}; this class owns only the {@link ObjectMapper} configuration and the
 * file write, wrapping any {@link IOException} as an {@link OutputException} per the {@link
 * OutputRenderer} contract — this renderer must never fail the build.
 */
public final class SarifOutputRenderer implements OutputRenderer {

    private final Path outputFile;
    private final ObjectMapper mapper;

    public SarifOutputRenderer(Path outputFile) {
        this(outputFile, defaultMapper());
    }

    /** Package-visible-for-tests-friendly overload; also usable by callers with their own mapper config. */
    public SarifOutputRenderer(Path outputFile, ObjectMapper mapper) {
        this.outputFile = Objects.requireNonNull(outputFile, "outputFile");
        this.mapper = mapper == null ? defaultMapper() : mapper;
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public String name() {
        return "sarif";
    }

    @Override
    public void render(RankedReport report) throws OutputException {
        SarifModel.SarifLog log = SarifReportBuilder.build(report);
        try {
            Path parent = outputFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile.toFile(), log);
        } catch (IOException e) {
            throw new OutputException("Failed to write SARIF report to " + outputFile, e);
        }
    }
}
