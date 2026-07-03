package dev.reachlayer.core.spi;

import dev.reachlayer.core.model.Finding;
import java.util.List;

/**
 * Pluggable per-scanner ingestion adapter. Implementations normalize a native scanner export
 * (Fortify FVDL/FPR, Black Duck BDIO/JSON, ...) into the canonical {@link Finding} model without
 * modifying the scanner's own severity/CVSS judgement. This is the extension point future
 * connectors (Snyk, Semgrep, Checkmarx, ...) plug into.
 */
public interface ScannerConnector {

    /** Short identifier used as {@link Finding#source()}, e.g. {@code "fortify"}. */
    String sourceName();

    /** Returns true if this connector can handle the given source (by extension/content sniff). */
    boolean supports(ScanSource source);

    /** Parses the given export into canonical findings. Never throws for individual bad records. */
    List<Finding> ingest(ScanSource source) throws ConnectorException;
}
