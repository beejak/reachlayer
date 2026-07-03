package dev.reachlayer.connectors.fortify;

import java.util.List;
import java.util.Map;

/** Result of parsing an {@code audit.fvdl} document: raw vulnerabilities + classID-&gt;abstract text. */
record FvdlDocument(List<RawVulnerability> vulnerabilities, Map<String, String> abstractsByClassId) {}
