package dev.reachlayer.core.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

/**
 * Loads {@code reachlayer.yml}. Every field is optional — any field missing from the file (or
 * the file itself being absent) falls back to {@link ReachlayerConfig#defaults()}, so the tool
 * is fully functional with zero configuration.
 *
 * <pre>
 * scoring:
 *   cvssWeight: 0.5
 *   exploitWeight: 0.5
 *   reachableMultiplier: 1.0
 *   unreachableMultiplier: 0.4
 *   unknownMultiplier: 0.7
 *   internetFacingWeight: 0.15
 *   touchesAuthWeight: 0.1
 *   touchesPiiWeight: 0.1
 *   touchesSecretsWeight: 0.1
 *   blastRadiusCap: 1.5
 * advisor:
 *   provider: noop
 *   topNForLlm: 5
 * output:
 *   topN: 5
 *   commentMarker: "&lt;!-- reachlayer:report --&gt;"
 * entryPoints:
 *   extraAnnotations:
 *     - "com.example.scheduling.Scheduled"
 *   extraClasses:
 *     - "com.example.jobs.NightlyReportJob"
 * </pre>
 *
 * See {@code docs/configuration.md} for the full reference.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static ReachlayerConfig loadDefaults() {
        return ReachlayerConfig.defaults();
    }

    public static ReachlayerConfig load(Path path) throws IOException {
        if (path == null || !Files.isRegularFile(path)) {
            return ReachlayerConfig.defaults();
        }
        try (InputStream in = Files.newInputStream(path)) {
            return load(in);
        }
    }

    @SuppressWarnings("unchecked")
    public static ReachlayerConfig load(InputStream in) {
        Yaml yaml = new Yaml();
        Object loaded = yaml.load(in);
        if (!(loaded instanceof Map)) {
            return ReachlayerConfig.defaults();
        }
        Map<String, Object> root = (Map<String, Object>) loaded;
        ScoringWeights defaultScoring = ScoringWeights.defaults();
        Map<String, Object> scoringMap = section(root, "scoring");
        ScoringWeights scoring = new ScoringWeights(
                doubleOr(scoringMap, "cvssWeight", defaultScoring.cvssWeight()),
                doubleOr(scoringMap, "exploitWeight", defaultScoring.exploitWeight()),
                doubleOr(scoringMap, "reachableMultiplier", defaultScoring.reachableMultiplier()),
                doubleOr(scoringMap, "unreachableMultiplier", defaultScoring.unreachableMultiplier()),
                doubleOr(scoringMap, "unknownMultiplier", defaultScoring.unknownMultiplier()),
                doubleOr(scoringMap, "internetFacingWeight", defaultScoring.internetFacingWeight()),
                doubleOr(scoringMap, "touchesAuthWeight", defaultScoring.touchesAuthWeight()),
                doubleOr(scoringMap, "touchesPiiWeight", defaultScoring.touchesPiiWeight()),
                doubleOr(scoringMap, "touchesSecretsWeight", defaultScoring.touchesSecretsWeight()),
                doubleOr(scoringMap, "blastRadiusCap", defaultScoring.blastRadiusCap()));

        AdvisorConfig defaultAdvisor = AdvisorConfig.defaults();
        Map<String, Object> advisorMap = section(root, "advisor");
        AdvisorConfig advisor = new AdvisorConfig(
                stringOr(advisorMap, "provider", defaultAdvisor.provider()),
                intOr(advisorMap, "topNForLlm", defaultAdvisor.topNForLlm()));

        OutputConfig defaultOutput = OutputConfig.defaults();
        Map<String, Object> outputMap = section(root, "output");
        OutputConfig output = new OutputConfig(
                intOr(outputMap, "topN", defaultOutput.topN()),
                stringOr(outputMap, "commentMarker", defaultOutput.commentMarker()));

        Map<String, Object> entryPointsMap = section(root, "entryPoints");
        EntryPointOverrides entryPoints = new EntryPointOverrides(
                stringListOr(entryPointsMap, "extraAnnotations"), stringListOr(entryPointsMap, "extraClasses"));

        return new ReachlayerConfig(scoring, advisor, output, entryPoints);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> section(Map<String, Object> root, String key) {
        Object value = root.get(key);
        return value instanceof Map ? (Map<String, Object>) value : Map.of();
    }

    private static double doubleOr(Map<String, Object> map, String key, double fallback) {
        Object v = map.get(key);
        return v instanceof Number n ? n.doubleValue() : fallback;
    }

    private static int intOr(Map<String, Object> map, String key, int fallback) {
        Object v = map.get(key);
        return v instanceof Number n ? n.intValue() : fallback;
    }

    private static String stringOr(Map<String, Object> map, String key, String fallback) {
        Object v = map.get(key);
        return v instanceof String s ? s : fallback;
    }

    /** Absent, non-list, or non-string-element entries are dropped rather than failing to parse. */
    private static List<String> stringListOr(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (!(v instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object element : list) {
            if (element instanceof String s) {
                out.add(s);
            }
        }
        return out;
    }
}
