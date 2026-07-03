package dev.reachlayer.core.spi;

import dev.reachlayer.core.model.Component;
import java.util.Set;

/**
 * Source of vulnerable-method signatures for a given component + CVE, e.g. OSV/GHSA advisory
 * data or an ingested OWASP dep-scan/atom reachables slice. Where a source has no
 * function-level granularity for a given CVE, it should return a single
 * {@link MethodSignature#anyMethodOf(String)} wildcard per affected class (or an empty set if
 * even the affected class is unknown), so callers can fall back to component-level reachability.
 */
public interface SignatureSource {

    /** Short identifier, e.g. {@code "osv"}. */
    String name();

    /** Vulnerable method signatures for the given component/CVE. Empty if none are known. */
    Set<MethodSignature> vulnerableMethods(Component component, String cveId);
}
