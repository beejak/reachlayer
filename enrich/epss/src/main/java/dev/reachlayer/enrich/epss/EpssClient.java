package dev.reachlayer.enrich.epss;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.reachlayer.core.model.Epss;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Locally-cached EPSS (Exploit Prediction Scoring System) client. See PLAN.md §6 and §9 risk 7:
 * EPSS is refreshed daily upstream, so a same-day cache hit never re-fetches, and any HTTP
 * failure degrades gracefully to stale cache data (or "no data") rather than throwing.
 *
 * <p>Cache file (JSON, one per {@code cacheDir}, named {@code epss-cache.json}):
 *
 * <pre>{@code
 * {
 *   "asOf": "2024-06-01",
 *   "scores": {
 *     "CVE-2021-44228": { "score": 0.974730000, "percentile": 0.999720000, "asOf": "2024-01-01" }
 *   }
 * }
 * }</pre>
 *
 * <p>The top-level {@code asOf} is the cache-file's "last refreshed" date, used purely as the
 * daily TTL marker. Each score's own {@code asOf} is the date the upstream EPSS API reported for
 * that score, which may differ (a CVE's score can be older than the last time the cache file was
 * touched, if it wasn't re-requested).
 */
public final class EpssClient {

    private static final Logger log = LoggerFactory.getLogger(EpssClient.class);

    private static final String EPSS_ENDPOINT = "https://api.first.org/data/v1/epss";
    private static final String CACHE_FILE_NAME = "epss-cache.json";

    private final HttpFetcher httpFetcher;
    private final Path cacheDir;
    private final Supplier<LocalDate> today;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public EpssClient(HttpFetcher httpFetcher, Path cacheDir) {
        this(httpFetcher, cacheDir, LocalDate::now);
    }

    public EpssClient(HttpFetcher httpFetcher, Path cacheDir, Supplier<LocalDate> today) {
        this.httpFetcher = httpFetcher;
        this.cacheDir = cacheDir;
        this.today = today;
    }

    /**
     * Looks up EPSS scores for the given CVE ids. Never throws: on upstream failure it falls back
     * to whatever is cached (even if stale), and simply omits CVEs it has no data for at all.
     */
    public Map<String, Epss> lookup(List<String> cveIds) {
        List<String> distinct = cveIds.stream().distinct().toList();
        if (distinct.isEmpty()) {
            return Map.of();
        }

        CacheFile cache = readCache();
        String todayStr = today.get().toString();
        boolean cacheFresh = cache != null && todayStr.equals(cache.asOf());

        Map<String, Epss> result = new LinkedHashMap<>();
        List<String> missing = new ArrayList<>();
        for (String cve : distinct) {
            CachedScore cached = cache == null ? null : cache.scores().get(cve);
            if (cacheFresh && cached != null) {
                result.put(cve, toEpss(cached));
            } else {
                missing.add(cve);
            }
        }

        if (missing.isEmpty()) {
            return result;
        }

        Map<String, Epss> fetched;
        try {
            fetched = fetchFromApi(missing);
        } catch (IOException e) {
            log.warn("EPSS fetch failed ({}); falling back to cache for {} CVE(s)", e.getMessage(), missing.size());
            if (cache != null) {
                for (String cve : missing) {
                    CachedScore cached = cache.scores().get(cve);
                    if (cached != null) {
                        result.put(cve, toEpss(cached));
                    }
                }
            }
            return result;
        }

        result.putAll(fetched);

        Map<String, CachedScore> mergedScores = new LinkedHashMap<>();
        if (cache != null) {
            mergedScores.putAll(cache.scores());
        }
        for (Map.Entry<String, Epss> entry : fetched.entrySet()) {
            Epss epss = entry.getValue();
            mergedScores.put(entry.getKey(), new CachedScore(epss.score(), epss.percentile(), epss.asOf()));
        }
        writeCache(new CacheFile(todayStr, mergedScores));

        return result;
    }

    private Map<String, Epss> fetchFromApi(List<String> cveIds) throws IOException {
        String cveParam = String.join(",", cveIds);
        URI uri = URI.create(EPSS_ENDPOINT + "?cve=" + cveParam);
        String body = httpFetcher.fetch(uri);

        ApiResponse response;
        try {
            response = objectMapper.readValue(body, ApiResponse.class);
        } catch (IOException e) {
            throw new IOException("Malformed EPSS API response: " + e.getMessage(), e);
        }

        Map<String, Epss> result = new LinkedHashMap<>();
        if (response.data() != null) {
            for (ApiEntry entry : response.data()) {
                if (entry.cve() == null) {
                    continue;
                }
                try {
                    double score = Double.parseDouble(entry.epss());
                    double percentile = Double.parseDouble(entry.percentile());
                    result.put(entry.cve(), new Epss(score, percentile, entry.date()));
                } catch (NumberFormatException e) {
                    log.warn("Skipping EPSS entry for {} with unparseable score/percentile", entry.cve());
                }
            }
        }
        return result;
    }

    private CacheFile readCache() {
        Path cacheFile = cacheDir.resolve(CACHE_FILE_NAME);
        if (!Files.isRegularFile(cacheFile)) {
            return null;
        }
        try {
            String content = Files.readString(cacheFile, StandardCharsets.UTF_8);
            return objectMapper.readValue(content, CacheFile.class);
        } catch (IOException e) {
            log.warn("Could not read EPSS cache at {} ({}); ignoring cache", cacheFile, e.getMessage());
            return null;
        }
    }

    private void writeCache(CacheFile cacheFile) {
        Path path = cacheDir.resolve(CACHE_FILE_NAME);
        try {
            Files.createDirectories(cacheDir);
            String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(cacheFile);
            Files.writeString(path, json, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Could not write EPSS cache at {} ({}); continuing without persisting", path, e.getMessage());
        }
    }

    private static Epss toEpss(CachedScore cached) {
        return new Epss(cached.score(), cached.percentile(), cached.asOf());
    }

    /** Shape of the {@code https://api.first.org/data/v1/epss} JSON response. */
    private record ApiResponse(String status, List<ApiEntry> data) {
    }

    private record ApiEntry(String cve, String epss, String percentile, String date) {
    }

    /** Shape of the on-disk cache file. */
    private record CacheFile(String asOf, Map<String, CachedScore> scores) {
    }

    private record CachedScore(double score, double percentile, String asOf) {
    }
}
