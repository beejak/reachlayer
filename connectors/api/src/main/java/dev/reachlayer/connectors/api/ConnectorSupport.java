package dev.reachlayer.connectors.api;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Small shared helpers used by more than one {@code ScannerConnector} implementation. */
public final class ConnectorSupport {

    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d{4,}");
    private static final Pattern CWE_PATTERN = Pattern.compile("(?:CWE-)?(\\d{1,4})");

    private ConnectorSupport() {}

    /** Extracts all CVE ids mentioned anywhere in the given text, in order of appearance. */
    public static List<String> extractCves(String text) {
        List<String> found = new ArrayList<>();
        if (text == null) {
            return found;
        }
        Matcher m = CVE_PATTERN.matcher(text);
        while (m.find()) {
            found.add(m.group());
        }
        return found;
    }

    /** Normalizes a CWE reference like {@code "89"} or {@code "CWE-89"} to {@code "CWE-89"}. */
    public static String normalizeCwe(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        Matcher m = CWE_PATTERN.matcher(raw.trim());
        if (m.matches()) {
            return "CWE-" + m.group(1);
        }
        return raw.trim();
    }

    /** Best-effort mapping of scanner-specific severity strings to a normalized display form. */
    public static String normalizeSeverity(String raw) {
        if (raw == null || raw.isBlank()) {
            return "unknown";
        }
        return raw.trim();
    }
}
