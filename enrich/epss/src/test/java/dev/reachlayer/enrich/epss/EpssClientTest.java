package dev.reachlayer.enrich.epss;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Epss;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EpssClientTest {

    private static final String CANNED_RESPONSE =
            """
            {
              "status": "OK",
              "data": [
                { "cve": "CVE-2021-44228", "epss": "0.974730000", "percentile": "0.999720000", "date": "2024-01-01" },
                { "cve": "CVE-2022-1234", "epss": "0.012340000", "percentile": "0.500000000", "date": "2024-01-01" }
              ]
            }
            """;

    @TempDir
    Path tempDir;

    @Test
    void firstCallFetchesAndCachesResults() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        EpssClient client = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        Map<String, Epss> result = client.lookup(List.of("CVE-2021-44228", "CVE-2022-1234"));

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(result).hasSize(2);
        Epss log4Shell = result.get("CVE-2021-44228");
        assertThat(log4Shell.score()).isEqualTo(0.97473);
        assertThat(log4Shell.percentile()).isEqualTo(0.99972);
        assertThat(log4Shell.asOf()).isEqualTo("2024-01-01");
    }

    @Test
    void secondCallWithinSameDayDoesNotRefetch() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        EpssClient client = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        client.lookup(List.of("CVE-2021-44228", "CVE-2022-1234"));
        Map<String, Epss> secondResult = client.lookup(List.of("CVE-2021-44228", "CVE-2022-1234"));

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(secondResult).hasSize(2);
    }

    @Test
    void newClientInstanceSameDayReusesDiskCache() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        EpssClient first = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        first.lookup(List.of("CVE-2021-44228"));

        EpssClient second = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        Map<String, Epss> result = second.lookup(List.of("CVE-2021-44228"));

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(result).containsKey("CVE-2021-44228");
    }

    @Test
    void staleCacheIsRefetched() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        EpssClient day1Client = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        day1Client.lookup(List.of("CVE-2021-44228"));

        EpssClient day2Client = new EpssClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 2));
        day2Client.lookup(List.of("CVE-2021-44228"));

        assertThat(fetchCount.get()).isEqualTo(2);
    }

    @Test
    void fetchFailureFallsBackToExistingCache() {
        HttpFetcher workingFetcher = uri -> CANNED_RESPONSE;
        EpssClient warmupClient = new EpssClient(workingFetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        warmupClient.lookup(List.of("CVE-2021-44228"));

        HttpFetcher failingFetcher = uri -> {
            throw new IOException("upstream is down");
        };
        // A later "day" so the cache is considered stale, forcing a fetch attempt that fails.
        EpssClient client = new EpssClient(failingFetcher, tempDir, () -> LocalDate.of(2024, 6, 5));

        Map<String, Epss> result = client.lookup(List.of("CVE-2021-44228"));

        assertThat(result).containsKey("CVE-2021-44228");
        assertThat(result.get("CVE-2021-44228").score()).isEqualTo(0.97473);
    }

    @Test
    void fetchFailureWithNoCacheReturnsEmptyMapWithoutThrowing() {
        HttpFetcher failingFetcher = uri -> {
            throw new IOException("upstream is down");
        };
        EpssClient client = new EpssClient(failingFetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        Map<String, Epss> result = client.lookup(List.of("CVE-2021-44228", "CVE-2022-1234"));

        assertThat(result).isEmpty();
    }

    @Test
    void fetchFailureWithPartialCacheReturnsOnlyCachedEntries() {
        HttpFetcher workingFetcher = uri -> CANNED_RESPONSE;
        EpssClient warmupClient = new EpssClient(workingFetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        warmupClient.lookup(List.of("CVE-2021-44228"));

        HttpFetcher failingFetcher = uri -> {
            throw new IOException("upstream is down");
        };
        EpssClient client = new EpssClient(failingFetcher, tempDir, () -> LocalDate.of(2024, 6, 5));

        Map<String, Epss> result = client.lookup(List.of("CVE-2021-44228", "CVE-9999-0000"));

        assertThat(result).containsOnlyKeys("CVE-2021-44228");
    }

    @Test
    void emptyRequestReturnsEmptyMapWithoutFetching() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        EpssClient client = new EpssClient(fetcher, tempDir);

        Map<String, Epss> result = client.lookup(List.of());

        assertThat(result).isEmpty();
        assertThat(fetchCount.get()).isZero();
    }

    @Test
    void jdkHttpFetcherRejectsUnreachableHost() {
        JdkHttpFetcher fetcher = new JdkHttpFetcher();
        URI uri = URI.create("http://localhost:1/definitely-not-listening");

        org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> fetcher.fetch(uri));
    }
}
