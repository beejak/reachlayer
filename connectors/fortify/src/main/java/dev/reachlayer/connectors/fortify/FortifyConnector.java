package dev.reachlayer.connectors.fortify;

import dev.reachlayer.connectors.api.ConnectorSupport;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.stream.XMLStreamException;

/**
 * {@link ScannerConnector} for Fortify SAST offline exports: either a raw {@code audit.fvdl} XML
 * file, or a {@code .fpr} archive (a zip containing {@code audit.fvdl} among other artifacts —
 * only {@code audit.fvdl} is parsed, per PLAN.md §6/§9).
 */
public final class FortifyConnector implements ScannerConnector {

    private static final String FVDL_ENTRY_NAME = "audit.fvdl";

    private final FvdlParser parser;

    public FortifyConnector() {
        this(new FvdlParser());
    }

    public FortifyConnector(FvdlParser parser) {
        this.parser = parser;
    }

    @Override
    public String sourceName() {
        return "fortify";
    }

    @Override
    public boolean supports(ScanSource source) {
        String name = source.path().getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".fvdl") || name.endsWith(".fpr");
    }

    @Override
    public List<Finding> ingest(ScanSource source) throws ConnectorException {
        Path path = source.path();
        try (InputStream fvdlStream = openFvdlStream(path)) {
            FvdlDocument document = parser.parse(fvdlStream);
            return toFindings(document);
        } catch (IOException | XMLStreamException e) {
            throw new ConnectorException("Failed to parse Fortify export " + path, e);
        }
    }

    private InputStream openFvdlStream(Path path) throws IOException, ConnectorException {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".fvdl")) {
            return Files.newInputStream(path);
        }
        // .fpr is a zip; find audit.fvdl inside it.
        ZipInputStream zip = new ZipInputStream(Files.newInputStream(path));
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            if (FVDL_ENTRY_NAME.equalsIgnoreCase(entry.getName())) {
                return zip; // caller closes; ZipInputStream reads only the current entry.
            }
        }
        zip.close();
        throw new ConnectorException("No " + FVDL_ENTRY_NAME + " entry found in " + path);
    }

    private List<Finding> toFindings(FvdlDocument document) {
        List<Finding> findings = new ArrayList<>();
        for (RawVulnerability v : document.vulnerabilities()) {
            Location location = new Location(v.sourcePath(), v.sourceLine(), v.sourceLineEnd(), null);
            String rule = v.ruleName();
            String severity = severityOf(v);
            List<String> cwe = new ArrayList<>();
            String normalizedCwe = ConnectorSupport.normalizeCwe(v.cwe());
            if (normalizedCwe != null) {
                cwe.add(normalizedCwe);
            }
            String description = document.abstractsByClassId().get(v.classId());

            Finding finding = Finding.builder()
                    .id(Finding.stableId("fortify", v.instanceId() != null ? v.instanceId() : rule, location, null))
                    .source("fortify")
                    .kind(FindingKind.SAST)
                    .cwe(cwe)
                    .location(location)
                    .severity(severity)
                    .cvss(Cvss.UNKNOWN) // Fortify SAST findings are not CVE/CVSS-scored.
                    .title(rule)
                    .description(description)
                    .putRawField("classId", v.classId())
                    .putRawField("kingdom", v.kingdom())
                    .putRawField("analyzerName", v.analyzerName())
                    .putRawField("confidence", v.confidence() == null ? null : String.valueOf(v.confidence()))
                    .putRawField("instanceId", v.instanceId())
                    .build();
            findings.add(finding);
        }
        return findings;
    }

    /** Fortify reports severity as a 0.0-5.0 float; kept as-is (stringified), never re-bucketed. */
    private static String severityOf(RawVulnerability v) {
        Double severity = v.instanceSeverity() != null ? v.instanceSeverity() : v.defaultSeverity();
        return severity == null ? "unknown" : String.valueOf(severity);
    }
}
