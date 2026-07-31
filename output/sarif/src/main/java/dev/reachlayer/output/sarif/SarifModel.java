package dev.reachlayer.output.sarif;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * A minimal SARIF 2.1.0 object graph — only the properties GitHub's code-scanning SARIF ingestion
 * (and most other SARIF consumers) actually read. Every record here serializes directly via
 * Jackson's native record support (no annotations needed except {@code $schema}, which isn't a
 * legal Java identifier). See the design spec for the exact field-by-field mapping rationale.
 */
public final class SarifModel {

    private SarifModel() {
    }

    public record SarifLog(@JsonProperty("$schema") String schema, String version, List<SarifRun> runs) {
    }

    public record SarifRun(SarifTool tool, List<SarifResult> results) {
    }

    public record SarifTool(SarifDriver driver) {
    }

    public record SarifDriver(String name, String informationUri, String version, List<SarifRule> rules) {
    }

    public record SarifRule(
            String id, String name, SarifText shortDescription, SarifText fullDescription, Map<String, Object> properties) {
    }

    public record SarifText(String text) {
    }

    public record SarifResult(
            String ruleId,
            int ruleIndex,
            String level,
            SarifText message,
            List<SarifLocation> locations,
            Map<String, String> partialFingerprints,
            Map<String, Object> properties) {
    }

    public record SarifLocation(SarifPhysicalLocation physicalLocation) {
    }

    public record SarifPhysicalLocation(SarifArtifactLocation artifactLocation, SarifRegion region) {
    }

    public record SarifArtifactLocation(String uri) {
    }

    public record SarifRegion(Integer startLine, Integer endLine) {
    }
}
