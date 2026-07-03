package dev.reachlayer.core.spi;

import java.nio.file.Path;
import java.util.Map;

/**
 * A scanner export handed to a {@link ScannerConnector}: a local file (FVDL/FPR XML, BDIO/JSON,
 * ...) plus free-form metadata a specific connector may need (e.g. project name overrides).
 */
public record ScanSource(Path path, Map<String, String> metadata) {

    public ScanSource {
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public static ScanSource ofPath(Path path) {
        return new ScanSource(path, Map.of());
    }
}
