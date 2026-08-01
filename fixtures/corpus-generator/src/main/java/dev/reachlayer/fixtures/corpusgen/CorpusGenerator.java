package dev.reachlayer.fixtures.corpusgen;

import java.util.List;
import java.util.Random;

/**
 * Generates a larger, varied, deterministic synthetic Fortify FVDL + Black Duck JSON corpus for
 * the evaluation pipeline (see {@code docs/evaluation-pipeline.md}). Every generated finding is
 * synthetic or references only public CVE identifiers -- no real vendor scanner output is ever
 * bundled or fetched, per {@code PLAN.md} §9 risk #6.
 *
 * <p>Three SAST "anchor" findings and two SCA "anchor" components deliberately reference the real
 * classes in {@code fixtures:vulnerable-spring-app} ({@code ReachableVulnerableComponent},
 * {@code UnreachableVulnerableComponent}, {@code VulnerableController}), so that running the full
 * pipeline against this corpus with {@code --classes} pointed at that module's compiled bytecode
 * produces genuine {@code REACHABLE}/{@code UNREACHABLE} reachability signal, not just {@code
 * UNKNOWN} -- exercising the real {@code ReachabilityTagger} end-to-end, not merely the identity
 * passthrough every other fixture in this repo exercises. The remaining {@code extraSastCount} /
 * {@code extraScaCount} findings are bulk synthetic filler (plus a handful of real, well-known
 * PUBLIC CVEs for realism) that intentionally is NOT part of the analyzed app, so it correctly
 * tags {@code UNKNOWN} -- a realistic "we don't know if this dependency's vulnerable code path is
 * used" scenario.
 */
public final class CorpusGenerator {

    private static final String FIXTURE_PACKAGE = "dev.reachlayer.fixtures.vulnapp";
    private static final String FIXTURE_SRC_PREFIX = "src/main/java/dev/reachlayer/fixtures/vulnapp/";

    private static final List<String> CWE_POOL =
            List.of("89", "22", "79", "798", "502", "611", "327", "352", "918", "330");

    private static final List<String> SCA_SEVERITY_POOL = List.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    /**
     * A handful of real, well-known PUBLIC CVEs for realism -- these are public advisory
     * identifiers, not proprietary scanner output (see the class Javadoc). None of these
     * libraries are actually compiled into {@code fixtures:vulnerable-spring-app}, so they are
     * expected to tag {@code UNKNOWN} ("component not observed") -- itself a useful, realistic
     * signal to exercise: a CVE match whose vulnerable code path can't be proven reachable in
     * this app.
     */
    private static final List<String[]> REAL_PUBLIC_CVE_POOL =
            List.of(
                    new String[] {"log4j-core", "2.14.1", "CVE-2021-44228", "502", "CRITICAL", "10.0"},
                    new String[] {"spring-webmvc", "5.3.18", "CVE-2022-22965", "94", "CRITICAL", "9.8"},
                    new String[] {"commons-text", "1.9", "CVE-2022-42889", "917", "CRITICAL", "9.8"},
                    new String[] {
                        "spring-cloud-function-context", "3.2.2", "CVE-2022-22963", "94", "HIGH", "8.1"
                    });

    private CorpusGenerator() {
    }

    /**
     * @param seed makes generation fully deterministic -- the same seed always produces byte-for-byte
     *     identical output, so evaluation runs are reproducible and diffable.
     * @param extraSastCount bulk synthetic SAST findings beyond the 3 fixed anchors
     * @param extraScaCount bulk synthetic SCA findings beyond the 2 fixed anchors
     */
    public static GeneratedCorpus generate(long seed, int extraSastCount, int extraScaCount) {
        Random rng = new Random(seed);

        StringBuilder vulns = new StringBuilder();
        StringBuilder descriptions = new StringBuilder();
        int sastCount = 0;

        sastCount += appendSastFinding(
                vulns,
                descriptions,
                "ANCHOR-REACHABLE",
                "SQL Injection",
                "89",
                4.0,
                FIXTURE_SRC_PREFIX + "ReachableVulnerableComponent.java",
                11,
                "Untrusted input reaches a SQL sink in a component this app's entry point actually calls.");
        sastCount += appendSastFinding(
                vulns,
                descriptions,
                "ANCHOR-UNREACHABLE",
                "Hardcoded Password",
                "798",
                3.0,
                FIXTURE_SRC_PREFIX + "UnreachableVulnerableComponent.java",
                11,
                "A hardcoded credential in a component nothing in this app ever calls.");
        sastCount += appendSastFinding(
                vulns,
                descriptions,
                "ANCHOR-CONTROLLER",
                "Missing CSRF Protection",
                "352",
                2.0,
                FIXTURE_SRC_PREFIX + "VulnerableController.java",
                22,
                "The entry point itself -- included so its own (trivially REACHABLE) reachability is exercised too.");

        for (int i = 0; i < extraSastCount; i++) {
            String cwe = CWE_POOL.get(rng.nextInt(CWE_POOL.size()));
            double severity = 1.0 + rng.nextInt(5);
            String classId = "SYNTH-SAST-" + i;
            String path = "src/main/java/dev/reachlayer/fixtures/vulnapp/synthetic/SyntheticFinding" + i + ".java";
            sastCount += appendSastFinding(
                    vulns,
                    descriptions,
                    classId,
                    "Synthetic Finding " + i,
                    cwe,
                    severity,
                    path,
                    10 + i,
                    "Synthetic finding #" + i + " for evaluation-corpus scale testing.");
        }

        StringBuilder fvdl = new StringBuilder();
        fvdl.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        fvdl.append("<FVDL xmlns=\"xmlns://www.fortify.com/schema/fvdl\" version=\"1.0\">\n");
        fvdl.append("  <Vulnerabilities>\n").append(vulns).append("  </Vulnerabilities>\n");
        fvdl.append(descriptions);
        fvdl.append("</FVDL>\n");

        StringBuilder components = new StringBuilder();
        int scaCount = 0;

        appendComponent(
                components,
                true,
                FIXTURE_PACKAGE + ".ReachableVulnerableComponent",
                "1.0.0",
                "maven",
                null,
                "89",
                "HIGH",
                7.5,
                "Reachable-component finding for evaluation-corpus anchoring.");
        scaCount++;
        appendComponent(
                components,
                false,
                FIXTURE_PACKAGE + ".UnreachableVulnerableComponent",
                "1.0.0",
                "maven",
                null,
                "798",
                "MEDIUM",
                5.0,
                "Unreachable-component finding for evaluation-corpus anchoring.");
        scaCount++;

        int realCvesUsed = Math.min(extraScaCount, REAL_PUBLIC_CVE_POOL.size());
        for (int i = 0; i < realCvesUsed; i++) {
            String[] real = REAL_PUBLIC_CVE_POOL.get(i);
            appendComponent(
                    components,
                    false,
                    real[0],
                    real[1],
                    "maven",
                    real[2],
                    real[3],
                    real[4],
                    Double.parseDouble(real[5]),
                    "Real, public CVE included for realism -- not part of this app's compiled classes, so it"
                            + " correctly tags UNKNOWN.");
            scaCount++;
        }

        for (int i = realCvesUsed; i < extraScaCount; i++) {
            String cwe = CWE_POOL.get(rng.nextInt(CWE_POOL.size()));
            String severity = SCA_SEVERITY_POOL.get(rng.nextInt(SCA_SEVERITY_POOL.size()));
            double cvss = 1.0 + rng.nextDouble() * 9.0;
            appendComponent(
                    components,
                    false,
                    "synthetic-lib-" + i,
                    "1.0." + i,
                    "maven",
                    "CVE-2030-" + (10000 + i),
                    cwe,
                    severity,
                    Math.round(cvss * 10.0) / 10.0,
                    "Synthetic component #" + i + " for evaluation-corpus scale testing.");
            scaCount++;
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"scanId\": \"evaluation-corpus-").append(seed).append("\",\n");
        json.append("  \"projectName\": \"reachlayer-evaluation-corpus\",\n");
        json.append("  \"projectVersion\": \"1.0.0\",\n");
        json.append("  \"components\": [\n").append(components).append("  ]\n");
        json.append("}\n");

        return new GeneratedCorpus(fvdl.toString(), json.toString(), sastCount, scaCount);
    }

    private static int appendSastFinding(
            StringBuilder vulns,
            StringBuilder descriptions,
            String classId,
            String type,
            String cwe,
            double severity,
            String sourcePath,
            int line,
            String abstractText) {
        vulns.append("    <Vulnerability>\n");
        vulns.append("      <ClassInfo>\n");
        vulns.append("        <ClassID>").append(classId).append("-CLASS</ClassID>\n");
        vulns.append("        <Kingdom>Input Validation and Representation</Kingdom>\n");
        vulns.append("        <Type>").append(escapeXml(type)).append("</Type>\n");
        vulns.append("        <AnalyzerName>dataflow</AnalyzerName>\n");
        vulns.append("        <DefaultSeverity>").append(severity).append("</DefaultSeverity>\n");
        vulns.append("        <CWE>").append(cwe).append("</CWE>\n");
        vulns.append("      </ClassInfo>\n");
        vulns.append("      <InstanceInfo>\n");
        vulns.append("        <InstanceID>").append(classId).append("-INSTANCE</InstanceID>\n");
        vulns.append("        <InstanceSeverity>").append(severity).append("</InstanceSeverity>\n");
        vulns.append("        <Confidence>3.0</Confidence>\n");
        vulns.append("      </InstanceInfo>\n");
        vulns.append("      <AnalysisInfo>\n");
        vulns.append("        <Unified>\n");
        vulns.append("          <Trace>\n");
        vulns.append("            <Primary>\n");
        vulns.append("              <Entry>\n");
        vulns.append("                <Node>\n");
        vulns.append("                  <SourceLocation path=\"")
                .append(escapeXml(sourcePath))
                .append("\" line=\"")
                .append(line)
                .append("\" lineEnd=\"")
                .append(line)
                .append("\" />\n");
        vulns.append("                </Node>\n");
        vulns.append("              </Entry>\n");
        vulns.append("            </Primary>\n");
        vulns.append("          </Trace>\n");
        vulns.append("        </Unified>\n");
        vulns.append("      </AnalysisInfo>\n");
        vulns.append("    </Vulnerability>\n");

        descriptions.append("  <Description classID=\"").append(classId).append("-CLASS\">\n");
        descriptions.append("    <Abstract>").append(escapeXml(abstractText)).append("</Abstract>\n");
        descriptions.append("  </Description>\n");
        return 1;
    }

    private static void appendComponent(
            StringBuilder components,
            boolean isFirst,
            String componentName,
            String componentVersion,
            String ecosystem,
            String cveId,
            String cwe,
            String severity,
            double cvssScore,
            String description) {
        if (!isFirst) {
            components.append(",\n");
        }
        components.append("    {\n");
        components.append("      \"componentName\": \"").append(escapeJson(componentName)).append("\",\n");
        components.append("      \"componentVersion\": \"").append(escapeJson(componentVersion)).append("\",\n");
        components.append("      \"ecosystem\": \"").append(escapeJson(ecosystem)).append("\",\n");
        components.append("      \"vulnerabilities\": [\n");
        components.append("        {\n");
        if (cveId != null) {
            components.append("          \"cveId\": \"").append(escapeJson(cveId)).append("\",\n");
        }
        components.append("          \"cwe\": \"CWE-").append(cwe).append("\",\n");
        components.append("          \"severity\": \"").append(severity).append("\",\n");
        components.append("          \"cvssScore\": ").append(cvssScore).append(",\n");
        components.append("          \"description\": \"").append(escapeJson(description)).append("\"\n");
        components.append("        }\n");
        components.append("      ]\n");
        components.append("    }\n");
    }

    private static String escapeXml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
