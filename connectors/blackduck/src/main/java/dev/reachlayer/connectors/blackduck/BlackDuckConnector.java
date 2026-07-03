package dev.reachlayer.connectors.blackduck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.connectors.api.ConnectorSupport;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
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
}
