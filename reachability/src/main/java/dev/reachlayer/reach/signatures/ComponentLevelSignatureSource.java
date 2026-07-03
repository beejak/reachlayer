package dev.reachlayer.reach.signatures;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.spi.MethodSignature;
import dev.reachlayer.core.spi.SignatureSource;
import java.util.Map;
import java.util.Set;

/**
 * {@link SignatureSource} that always has an answer, per PLAN.md §4/§9 risk 2: most OSV/GHSA
 * advisories don't carry function-level granularity, so the MVP default is component-level
 * reachability — "is any method of this vulnerable dependency reachable at all." A small hardcoded
 * table of well-known CVEs with real affected-method data is layered on top purely to demonstrate
 * the finer-grained path; production use should replace/extend that table with a real OSV/GHSA
 * feed or an ingested dep-scan/atom slice (both pluggable via the {@link SignatureSource} SPI).
 */
public final class ComponentLevelSignatureSource implements SignatureSource {

    /** component name -&gt; CVE id -&gt; known vulnerable methods. Illustrative only, not exhaustive. */
    private static final Map<String, Map<String, Set<MethodSignature>>> KNOWN_FINE_GRAINED =
            Map.of(
                    "log4j-core",
                            Map.of(
                                    "CVE-2021-44228",
                                    Set.of(
                                            new MethodSignature(
                                                    "org.apache.logging.log4j.core.lookup.JndiLookup", "lookup"))),
                    "org.apache.logging.log4j:log4j-core",
                            Map.of(
                                    "CVE-2021-44228",
                                    Set.of(
                                            new MethodSignature(
                                                    "org.apache.logging.log4j.core.lookup.JndiLookup", "lookup"))));

    @Override
    public String name() {
        return "component-level";
    }

    @Override
    public Set<MethodSignature> vulnerableMethods(Component component, String cveId) {
        if (component == null) {
            return Set.of();
        }
        Map<String, Set<MethodSignature>> byCve = KNOWN_FINE_GRAINED.get(component.name());
        if (byCve != null && cveId != null) {
            Set<MethodSignature> fineGrained = byCve.get(cveId);
            if (fineGrained != null && !fineGrained.isEmpty()) {
                return fineGrained;
            }
        }
        return Set.of(MethodSignature.anyMethodOf(component.name()));
    }
}
