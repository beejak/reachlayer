package dev.reachlayer.connectors.fortify;

import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Streaming (StAX/Woodstox) parser for Fortify {@code audit.fvdl} XML. FPRs can be large, so this
 * deliberately avoids building a DOM: it walks the stream once, tracking a small element-name
 * stack and accumulating only the handful of fields the scoring/reachability pipeline needs, per
 * PLAN.md §6 ("Streaming avoids OOM on big Fortify exports").
 *
 * <p>Covers the subset of the FVDL schema that is load-bearing for Reachlayer:
 * {@code Vulnerabilities/Vulnerability/{ClassInfo,InstanceInfo,AnalysisInfo/.../SourceLocation}}
 * and top-level {@code Description[@classID]/Abstract}.
 */
public final class FvdlParser {

    public FvdlDocument parse(InputStream in) throws XMLStreamException {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        // Harden against XXE: no DTDs, no external entities.
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);

        XMLStreamReader reader = factory.createXMLStreamReader(in);
        try {
            return parse(reader);
        } finally {
            reader.close();
        }
    }

    private FvdlDocument parse(XMLStreamReader reader) throws XMLStreamException {
        List<RawVulnerability> vulnerabilities = new ArrayList<>();
        Map<String, String> abstractsByClassId = new LinkedHashMap<>();
        Deque<String> path = new ArrayDeque<>();
        StringBuilder text = new StringBuilder();

        MutableVuln current = null;
        String currentDescriptionClassId = null;

        while (reader.hasNext()) {
            int event = reader.next();
            switch (event) {
                case XMLStreamConstants.START_ELEMENT -> {
                    String name = reader.getLocalName();
                    path.push(name);
                    text.setLength(0);

                    if ("Vulnerability".equals(name)) {
                        current = new MutableVuln();
                    } else if ("SourceLocation".equals(name) && current != null) {
                        current.sourcePath = reader.getAttributeValue(null, "path");
                        current.sourceLine = parseInt(reader.getAttributeValue(null, "line"));
                        current.sourceLineEnd = parseInt(reader.getAttributeValue(null, "lineEnd"));
                        current.snippet = reader.getAttributeValue(null, "snippet");
                    } else if ("Description".equals(name)) {
                        currentDescriptionClassId = reader.getAttributeValue(null, "classID");
                    }
                }
                case XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> text.append(reader.getText());
                case XMLStreamConstants.END_ELEMENT -> {
                    String name = reader.getLocalName();
                    String value = text.toString().trim();
                    text.setLength(0);

                    if (current != null) {
                        applyLeaf(current, path, name, value);
                    }
                    if ("Abstract".equals(name) && currentDescriptionClassId != null) {
                        abstractsByClassId.put(currentDescriptionClassId, value);
                    }
                    if ("Description".equals(name)) {
                        currentDescriptionClassId = null;
                    }
                    if ("Vulnerability".equals(name) && current != null) {
                        vulnerabilities.add(current.toImmutable());
                        current = null;
                    }
                    path.pop();
                }
                default -> {
                    // ignore comments, processing instructions, whitespace, etc.
                }
            }
        }
        return new FvdlDocument(vulnerabilities, abstractsByClassId);
    }

    private static void applyLeaf(MutableVuln vuln, Deque<String> path, String name, String value) {
        String parent = nthParent(path, 1); // element enclosing `name` (path still has `name` on top)
        switch (name) {
            case "ClassID" -> {
                if ("ClassInfo".equals(parent)) vuln.classId = value;
            }
            case "Kingdom" -> {
                if ("ClassInfo".equals(parent)) vuln.kingdom = value;
            }
            case "Type" -> {
                if ("ClassInfo".equals(parent)) vuln.type = value;
            }
            case "Subtype" -> {
                if ("ClassInfo".equals(parent)) vuln.subtype = value;
            }
            case "AnalyzerName" -> {
                if ("ClassInfo".equals(parent)) vuln.analyzerName = value;
            }
            case "DefaultSeverity" -> {
                if ("ClassInfo".equals(parent)) vuln.defaultSeverity = parseDouble(value);
            }
            case "CWE" -> {
                if ("ClassInfo".equals(parent)) vuln.cwe = value;
            }
            case "InstanceID" -> {
                if ("InstanceInfo".equals(parent)) vuln.instanceId = value;
            }
            case "InstanceSeverity" -> {
                if ("InstanceInfo".equals(parent)) vuln.instanceSeverity = parseDouble(value);
            }
            case "Confidence" -> {
                if ("InstanceInfo".equals(parent)) vuln.confidence = parseDouble(value);
            }
            default -> {
                // not a field we need
            }
        }
    }

    /** Returns the element name {@code n} levels above the top of the stack ({@code n=1} = parent). */
    private static String nthParent(Deque<String> path, int n) {
        var it = path.iterator();
        for (int i = 0; i < n && it.hasNext(); i++) {
            it.next();
        }
        return it.hasNext() ? it.next() : null;
    }

    private static Double parseDouble(String s) {
        try {
            return s == null || s.isBlank() ? null : Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Integer parseInt(String s) {
        try {
            return s == null || s.isBlank() ? null : Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Scratch, mutable accumulator for a single vulnerability while it's being streamed in. */
    private static final class MutableVuln {
        String classId;
        String kingdom;
        String type;
        String subtype;
        String analyzerName;
        Double defaultSeverity;
        String cwe;
        String instanceId;
        Double instanceSeverity;
        Double confidence;
        String sourcePath;
        Integer sourceLine;
        Integer sourceLineEnd;
        String snippet;

        RawVulnerability toImmutable() {
            return new RawVulnerability(
                    classId,
                    kingdom,
                    type,
                    subtype,
                    analyzerName,
                    defaultSeverity,
                    cwe,
                    instanceId,
                    instanceSeverity,
                    confidence,
                    sourcePath,
                    sourceLine,
                    sourceLineEnd,
                    snippet);
        }
    }
}
