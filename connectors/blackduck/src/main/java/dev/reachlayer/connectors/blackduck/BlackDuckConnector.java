package dev.reachlayer.connectors.blackduck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.connectors.api.ConnectorSupport;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.spi.ConnectorException;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.core.spi.ScannerConnector;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * {@link ScannerConnector} for Black Duck SCA offline exports.
 *
 * <p>Real Black Duck BDIO output is a JSON-LD dependency graph plus a separate vulnerability
 * REST/JSON payload; for MVP readability this connector accepts a simplified, flattened
 * per-component-vulnerability JSON shape (documented in {@code docs/connectors.md}) that carries
 * the same load-bearing fields: component coordinate, CVE, CWE, severity, and CVSS. Swapping in a
 * full BDIO JSON-LD reader later only changes this class, not the {@link Finding} contract.
 *
 * <p>Also accepts an optional per-vulnerability {@code vendorReachability} field
 * ({@code "REACHABLE"}/{@code "UNREACHABLE"}/{@code "UNKNOWN"}, case-insensitive), surfaced on
 * {@link Finding#vendorReachability()} as a second signal alongside Reachlayer's own computed
 * reachability tag — see {@code docs/connectors.md} for why (Black Duck Detect's native
 * "Vulnerability Impact Analysis" may already populate a field like this in a real export). This
 * is Reachlayer's own invented representation for the MVP's simplified schema, not a verified
 * real-world Black Duck field name.
 */
public final class BlackDuckConnector implements ScannerConnector {

    private final ObjectMapper mapper;

    public BlackDuckConnector() {
        this(new ObjectMapper());
    }

    public BlackDuckConnector(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String sourceName() {
        return "blackduck";
    }

    @Override
    public boolean supports(ScanSource source) {
        String name = source.path().getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".json") || name.endsWith(".bdio");
    }

    @Override
    public List<Finding> ingest(ScanSource source) throws ConnectorException {
        Path path = source.path();
        JsonNode root;
        try {
            root = mapper.readTree(path.toFile());
        } catch (IOException e) {
            throw new ConnectorException("Failed to parse Black Duck export " + path, e);
        }
        if (root == null || root.isMissingNode()) {
            throw new ConnectorException("Empty Black Duck export " + path);
        }
        return toFindings(root);
    }

    private List<Finding> toFindings(JsonNode root) {
        List<Finding> findings = new ArrayList<>();
        String scanId = textOrNull(root, "scanId");
        String projectName = textOrNull(root, "projectName");
        String projectVersion = textOrNull(root, "projectVersion");

        for (JsonNode componentNode : root.path("components")) {
            Component component = new Component(
                    textOrNull(componentNode, "componentName"),
                    textOrNull(componentNode, "componentVersion"),
                    textOrNull(componentNode, "ecosystem"));

            for (JsonNode vulnNode : componentNode.path("vulnerabilities")) {
                String cveId = textOrNull(vulnNode, "cveId");
                String cwe = ConnectorSupport.normalizeCwe(textOrNull(vulnNode, "cwe"));
                String severity = ConnectorSupport.normalizeSeverity(textOrNull(vulnNode, "severity"));
                Double cvssScore = vulnNode.hasNonNull("cvssScore") ? vulnNode.get("cvssScore").asDouble() : null;
                String cvssVector = textOrNull(vulnNode, "cvssVector");
                String description = textOrNull(vulnNode, "description");
                Reachability vendorReachability = parseVendorReachability(textOrNull(vulnNode, "vendorReachability"));

                Location location = Location.unknown();
                Finding finding = Finding.builder()
                        .id(Finding.stableId("blackduck", cveId, location, component))
                        .source("blackduck")
                        .kind(FindingKind.SCA)
                        .cve(cveId == null ? List.of() : List.of(cveId))
                        .cwe(cwe == null ? List.of() : List.of(cwe))
                        .component(component)
                        .location(location)
                        .severity(severity)
                        .cvss(new Cvss(cvssScore, cvssVector))
                        .title(cveId != null ? cveId : component.coordinate())
                        .description(description)
                        .vendorReachability(vendorReachability)
                        .putRawField("scanId", scanId)
                        .putRawField("projectName", projectName)
                        .putRawField("projectVersion", projectVersion)
                        .build();
                findings.add(finding);
            }
        }
        return findings;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    /** Tolerates absent or unrecognized values by returning {@code null} rather than throwing — an
     * optional field with an unexpected value must never fail ingestion of the finding it's on. */
    private static Reachability parseVendorReachability(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Reachability.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
