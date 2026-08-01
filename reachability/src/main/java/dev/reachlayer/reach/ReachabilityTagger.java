package dev.reachlayer.reach;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.Reachability;
import dev.reachlayer.core.pipeline.ReachabilityStage;
import dev.reachlayer.core.spi.MethodSignature;
import dev.reachlayer.core.spi.SignatureSource;
import dev.reachlayer.reach.callgraph.CallGraphBuilder;
import dev.reachlayer.reach.callgraph.CallGraphResult;
import dev.reachlayer.reach.entrypoints.EntryPoint;
import dev.reachlayer.reach.entrypoints.EntryPointScanner;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Orchestrates reachability tagging: builds a SootUp CHA call graph once over the given "app under
 * analysis" classes/jar (cached for the lifetime of this instance), then tags each {@link Finding}
 * as {@code REACHABLE}, {@code UNREACHABLE}, or {@code UNKNOWN} by intersecting the call graph with
 * vulnerable-method signatures (for SCA findings that carry a {@link Component}) or with the
 * finding's own source location (for SAST findings with no component).
 *
 * <p>Per PLAN.md §9 risk 1, static reachability is unsound: this class never throws out of {@link
 * #tag(List)} for an analysis failure. Any problem building or querying the call graph degrades
 * every affected finding to {@code UNKNOWN} with an explanatory {@code reachEvidence}, rather than
 * failing the pipeline or — worse — silently mis-tagging a finding as {@code UNREACHABLE}.
 * Reachability is additive, never suppressive.
 */
public final class ReachabilityTagger implements ReachabilityStage {

    private static final Logger log = LoggerFactory.getLogger(ReachabilityTagger.class);

    private static final List<String> SOURCE_ROOT_MARKERS =
            List.of("src/main/java/", "src/test/java/", "src/main/kotlin/", "src/test/kotlin/");

    private final List<SignatureSource> signatureSources;
    private final CallGraphResult callGraphResult;
    private final String unavailableReason;

    public ReachabilityTagger(Path classesRoot, SignatureSource signatureSource) {
        this(classesRoot, List.of(signatureSource));
    }

    public ReachabilityTagger(Path classesRoot, List<SignatureSource> signatureSources) {
        this.signatureSources = List.copyOf(signatureSources);

        CallGraphResult result = null;
        String reason = null;
        try {
            List<EntryPoint> entryPoints = new EntryPointScanner().discover(classesRoot);
            result = new CallGraphBuilder().build(classesRoot, entryPoints);
        } catch (Exception e) {
            reason = shortReason(e);
            log.warn("Reachability analysis unavailable for {}: {}", classesRoot, reason);
        }
        this.callGraphResult = result;
        this.unavailableReason = reason;
    }

    @Override
    public List<Finding> tag(List<Finding> findings) {
        if (callGraphResult == null) {
            String evidence = "reachability analysis unavailable: " + unavailableReason;
            List<Finding> out = new ArrayList<>(findings.size());
            for (Finding f : findings) {
                Finding tagged = f.toBuilder().reachability(Reachability.UNKNOWN).reachEvidence(evidence).build();
                out.add(noteVendorDisagreement(tagged));
            }
            return out;
        }

        List<Finding> out = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            out.add(tagOne(f));
        }
        return out;
    }

    private Finding tagOne(Finding finding) {
        Finding tagged;
        try {
            tagged = finding.component() != null ? tagComponentFinding(finding) : tagSastFinding(finding);
        } catch (RuntimeException e) {
            String reason = shortReason(e);
            log.warn("Reachability tagging failed for finding {}: {}", finding.id(), reason);
            tagged = finding
                    .toBuilder()
                    .reachability(Reachability.UNKNOWN)
                    .reachEvidence("reachability analysis unavailable: " + reason)
                    .build();
        }
        return noteVendorDisagreement(tagged);
    }

    /**
     * When the scanner's own export carried a {@link Finding#vendorReachability()} verdict (e.g.
     * Black Duck Detect's native impact analysis — see {@code docs/connectors.md}) that differs
     * from Reachlayer's own computed tag, appends a note to {@code reachEvidence} rather than
     * silently ignoring or preferring one signal over the other (PLAN.md §2 principle 2). Agreement
     * is not noted — it isn't actionable the way a difference is. A difference where Reachlayer's
     * own tag is {@code UNKNOWN} (inconclusive, not a real claim) is worded differently from a
     * genuine disagreement between two concrete verdicts.
     */
    private static Finding noteVendorDisagreement(Finding tagged) {
        Reachability vendor = tagged.vendorReachability();
        if (vendor == null || vendor == tagged.reachability()) {
            return tagged;
        }
        String note =
                tagged.reachability() == Reachability.UNKNOWN
                        ? "; vendor-reported reachability (" + vendor.wireValue()
                                + ") noted, Reachlayer's own analysis was inconclusive"
                        : "; disagrees with vendor-reported reachability (" + vendor.wireValue() + ")";
        return tagged.toBuilder().reachEvidence(tagged.reachEvidence() + note).build();
    }

    private Finding tagComponentFinding(Finding finding) {
        Component component = finding.component();
        String cveId = finding.cve().isEmpty() ? null : finding.cve().get(0);

        Set<MethodSignature> vulnerableMethods = new LinkedHashSet<>();
        for (SignatureSource source : signatureSources) {
            vulnerableMethods.addAll(source.vulnerableMethods(component, cveId));
        }
        if (vulnerableMethods.isEmpty()) {
            return finding
                    .toBuilder()
                    .reachability(Reachability.UNKNOWN)
                    .reachEvidence("no vulnerable-method signature available for " + component.coordinate())
                    .build();
        }

        boolean anyObserved = false;
        for (MethodSignature signature : vulnerableMethods) {
            if (!callGraphResult.isClassObserved(signature.declaringClass())) {
                continue;
            }
            anyObserved = true;
            String methodNameOrNull = signature.isWildcard() ? null : signature.methodName();
            if (callGraphResult.isReachable(signature.declaringClass(), methodNameOrNull)) {
                String what =
                        signature.isWildcard()
                                ? "a method of " + signature.declaringClass()
                                : signature.declaringClass() + "." + signature.methodName() + "()";
                return finding
                        .toBuilder()
                        .reachability(Reachability.REACHABLE)
                        .reachEvidence(
                                what + " found in call graph, reachable from " + callGraphResult.entryPointSummary())
                        .build();
            }
        }
        if (!anyObserved) {
            return finding
                    .toBuilder()
                    .reachability(Reachability.UNKNOWN)
                    .reachEvidence("component not observed in analyzed classes")
                    .build();
        }
        return finding
                .toBuilder()
                .reachability(Reachability.UNREACHABLE)
                .reachEvidence("no call path found from any discovered entry point")
                .build();
    }

    private Finding tagSastFinding(Finding finding) {
        String file = finding.location() == null ? null : finding.location().file();
        String className = classNameFromSourcePath(file);
        if (className == null) {
            return finding
                    .toBuilder()
                    .reachability(Reachability.UNKNOWN)
                    .reachEvidence("unable to resolve class from source path")
                    .build();
        }
        if (!callGraphResult.isClassObserved(className)) {
            return finding
                    .toBuilder()
                    .reachability(Reachability.UNKNOWN)
                    .reachEvidence("component not observed in analyzed classes")
                    .build();
        }
        if (callGraphResult.isReachable(className, null)) {
            return finding
                    .toBuilder()
                    .reachability(Reachability.REACHABLE)
                    .reachEvidence(
                            "class "
                                    + className
                                    + " found in call graph, reachable from "
                                    + callGraphResult.entryPointSummary())
                    .build();
        }
        return finding
                .toBuilder()
                .reachability(Reachability.UNREACHABLE)
                .reachEvidence("no call path found from any discovered entry point")
                .build();
    }

    /**
     * Best-effort mapping from a SAST finding's source-file path to a fully-qualified class name,
     * e.g. {@code src/main/java/dev/reachlayer/fixtures/vulnapp/UserController.java} -&gt; {@code
     * dev.reachlayer.fixtures.vulnapp.UserController}. Returns {@code null} when the path doesn't
     * look like a Java source file under a recognizable source root.
     */
    static String classNameFromSourcePath(String file) {
        if (file == null || file.isBlank()) {
            return null;
        }
        String normalized = file.replace('\\', '/');
        for (String marker : SOURCE_ROOT_MARKERS) {
            int idx = normalized.indexOf(marker);
            if (idx >= 0) {
                normalized = normalized.substring(idx + marker.length());
                break;
            }
        }
        if (!normalized.endsWith(".java")) {
            return null;
        }
        normalized = normalized.substring(0, normalized.length() - ".java".length());
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isBlank()) {
            return null;
        }
        return normalized.replace('/', '.');
    }

    private static String shortReason(Exception e) {
        String message = e.getMessage();
        return e.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + message);
    }
}
