package dev.reachlayer.enrich.kev;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KevClientTest {

    private static final String CANNED_RESPONSE =
            """
            {
              "catalogVersion": "2024.06.01",
              "dateReleased": "2024-06-01T00:00:00.000Z",
              "count": 2,
              "vulnerabilities": [
                { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j" },
                { "cveID": "CVE-2022-1234", "vendorProject": "Example", "product": "Widget" }
              ]
            }
            """;

    @TempDir
    Path tempDir;

    @Test
    void firstCallFetchesAndCachesCatalog() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        KevClient client = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        Set<String> result = client.knownExploitedCves();

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(result).containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2022-1234");
        assertThat(client.isKnownExploited("CVE-2021-44228")).isTrue();
        assertThat(client.isKnownExploited("CVE-9999-0000")).isFalse();
    }

    @Test
    void secondCallWithinSameDayDoesNotRefetch() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        KevClient client = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        client.knownExploitedCves();
        Set<String> second = client.knownExploitedCves();

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(second).hasSize(2);
    }

    @Test
    void newClientInstanceSameDayReusesDiskCache() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        KevClient first = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        first.knownExploitedCves();

        KevClient second = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        boolean isKnown = second.isKnownExploited("CVE-2021-44228");

        assertThat(fetchCount.get()).isEqualTo(1);
        assertThat(isKnown).isTrue();
    }

    @Test
    void staleCacheIsRefetched() {
        AtomicInteger fetchCount = new AtomicInteger();
        HttpFetcher fetcher = uri -> {
            fetchCount.incrementAndGet();
            return CANNED_RESPONSE;
        };
        KevClient day1 = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        day1.knownExploitedCves();

        KevClient day2 = new KevClient(fetcher, tempDir, () -> LocalDate.of(2024, 6, 2));
        day2.knownExploitedCves();

        assertThat(fetchCount.get()).isEqualTo(2);
    }

    @Test
    void fetchFailureFallsBackToStaleCache() {
        HttpFetcher workingFetcher = uri -> CANNED_RESPONSE;
        KevClient warmup = new KevClient(workingFetcher, tempDir, () -> LocalDate.of(2024, 6, 1));
        warmup.knownExploitedCves();

        HttpFetcher failingFetcher = uri -> {
            throw new IOException("upstream is down");
        };
        KevClient client = new KevClient(failingFetcher, tempDir, () -> LocalDate.of(2024, 6, 5));

        Set<String> result = client.knownExploitedCves();

        assertThat(result).containsExactlyInAnyOrder("CVE-2021-44228", "CVE-2022-1234");
        assertThat(client.isKnownExploited("CVE-2021-44228")).isTrue();
    }

    @Test
    void fetchFailureWithNoCacheReturnsEmptySetWithoutThrowing() {
        HttpFetcher failingFetcher = uri -> {
            throw new IOException("upstream is down");
        };
        KevClient client = new KevClient(failingFetcher, tempDir, () -> LocalDate.of(2024, 6, 1));

        Set<String> result = client.knownExploitedCves();

        assertThat(result).isEmpty();
        assertThat(client.isKnownExploited("CVE-2021-44228")).isFalse();
    }

    @Test
    void jdkHttpFetcherRejectsUnreachableHost() {
        JdkHttpFetcher fetcher = new JdkHttpFetcher();
        URI uri = URI.create("http://localhost:1/definitely-not-listening");

        org.junit.jupiter.api.Assertions.assertThrows(IOException.class, () -> fetcher.fetch(uri));
    }
}
