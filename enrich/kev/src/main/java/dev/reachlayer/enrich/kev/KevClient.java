package dev.reachlayer.enrich.kev;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Locally-cached client for the CISA Known Exploited Vulnerabilities (KEV) catalog. See PLAN.md
 * §6 and §9 risk 7: KEV has no webhook/push feed, so this refreshes on a daily TTL, and any HTTP
 * failure degrades gracefully to stale cache data (or "no KEV data") rather than throwing.
 *
 * <p><b>Phase 1 follow-up (documented scope limitation):</b> PLAN.md describes KEV refresh as a
 * "daily diff." This MVP client does a full refetch-and-replace of the catalog once per day
 * rather than computing an incremental diff against the previous catalog; a true incremental diff
 * (tracking additions/removals between catalog versions) is deferred to Phase 1.
 *
 * <p>Cache file (JSON, one per {@code cacheDir}, named {@code kev-cache.json}):
 *
 * <pre>{@code
 * {
 *   "asOf": "2024-06-01",
 *   "cveIds": ["CVE-2021-44228", "CVE-2023-12345"]
 * }
 * }</pre>
 */
public final class KevClient {

    private static final Logger log = LoggerFactory.getLogger(KevClient.class);

    private static final String KEV_ENDPOINT =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String CACHE_FILE_NAME = "kev-cache.json";

    private final HttpFetcher httpFetcher;
    private final Path cacheDir;
    private final Supplier<LocalDate> today;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public KevClient(HttpFetcher httpFetcher, Path cacheDir) {
        this(httpFetcher, cacheDir, LocalDate::now);
    }

    public KevClient(HttpFetcher httpFetcher, Path cacheDir, Supplier<LocalDate> today) {
        this.httpFetcher = httpFetcher;
        this.cacheDir = cacheDir;
        this.today = today;
    }

    /** Returns {@code true} if {@code cveId} is in the KEV catalog. Never throws. */
    public boolean isKnownExploited(String cveId) {
        return cveId != null && knownExploitedCves().contains(cveId);
    }

    /**
     * Returns the full set of known-exploited CVE ids, refreshing the catalog if the cache is
     * absent or stale (older than "today"). On upstream failure, falls back to whatever is
     * cached (even if stale); if nothing is cached, returns an empty set. Never throws.
     */
    public Set<String> knownExploitedCves() {
        CacheFile cache = readCache();
        String todayStr = today.get().toString();

        if (cache != null && todayStr.equals(cache.asOf())) {
            return new LinkedHashSet<>(cache.cveIds());
        }

        try {
            Set<String> fetched = fetchFromApi();
            writeCache(new CacheFile(todayStr, List.copyOf(fetched)));
            return fetched;
        } catch (IOException e) {
            log.warn("KEV fetch failed ({}); falling back to {}", e.getMessage(),
                    cache == null ? "empty result (no cache available)" : "stale cache");
            return cache == null ? Set.of() : new LinkedHashSet<>(cache.cveIds());
        }
    }

    private Set<String> fetchFromApi() throws IOException {
        String body = httpFetcher.fetch(URI.create(KEV_ENDPOINT));

        ApiResponse response;
        try {
            response = objectMapper.readValue(body, ApiResponse.class);
        } catch (IOException e) {
            throw new IOException("Malformed KEV catalog response: " + e.getMessage(), e);
        }

        Set<String> result = new LinkedHashSet<>();
        if (response.vulnerabilities() != null) {
            for (ApiVuln vuln : response.vulnerabilities()) {
                if (vuln.cveID() != null) {
                    result.add(vuln.cveID());
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
            log.warn("Could not read KEV cache at {} ({}); ignoring cache", cacheFile, e.getMessage());
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
            log.warn("Could not write KEV cache at {} ({}); continuing without persisting", path, e.getMessage());
        }
    }

    /** Shape of the CISA KEV catalog JSON response (only the fields this client needs). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ApiResponse(String catalogVersion, String dateReleased, Integer count, List<ApiVuln> vulnerabilities) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ApiVuln(String cveID) {
    }

    /** Shape of the on-disk cache file. */
    private record CacheFile(String asOf, List<String> cveIds) {
    }
}
