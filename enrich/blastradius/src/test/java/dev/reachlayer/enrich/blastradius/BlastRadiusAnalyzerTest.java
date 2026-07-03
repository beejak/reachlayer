package dev.reachlayer.enrich.blastradius;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Location;
import org.junit.jupiter.api.Test;

class BlastRadiusAnalyzerTest {

    private final BlastRadiusAnalyzer analyzer = new BlastRadiusAnalyzer();

    @Test
    void flagsAuthAndInternetFacingFromTitle() {
        Finding finding = Finding.builder()
                .id("f1")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("SQL Injection in AuthController")
                .description("User-supplied input is concatenated into a SQL query.")
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.touchesAuth()).isTrue();
        assertThat(result.internetFacing()).isTrue();
    }

    @Test
    void flagsSecretsFromComponentName() {
        Finding finding = Finding.builder()
                .id("f2")
                .source("blackduck")
                .kind(FindingKind.SCA)
                .title("Vulnerable dependency")
                .description("Outdated crypto library")
                .component(Component.of("com.example:PaymentSecretsVault", "2.3.1"))
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.touchesSecrets()).isTrue();
        assertThat(result.downstream()).containsExactly("com.example:PaymentSecretsVault@2.3.1");
    }

    @Test
    void flagsPiiFromDescription() {
        Finding finding = Finding.builder()
                .id("f3")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Data exposure")
                .description("Leaks the customer's email address and phone number in logs.")
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.touchesPii()).isTrue();
        assertThat(result.touchesAuth()).isFalse();
        assertThat(result.touchesSecrets()).isFalse();
    }

    @Test
    void flagsInternetFacingFromMethodSignature() {
        Finding finding = Finding.builder()
                .id("f4")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Path traversal")
                .description("File path built from request parameter.")
                .location(new Location("FileServlet.java", 42, 42, "FileServlet.doGet(HttpServletRequest, HttpServletResponse)"))
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.internetFacing()).isTrue();
    }

    @Test
    void blandFindingWithNoKeywordsYieldsAllFalse() {
        Finding finding = Finding.builder()
                .id("f5")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Minor code smell")
                .description("A loop could be simplified.")
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result).isEqualTo(BlastRadius.NONE);
    }

    @Test
    void findingWithNoComponentHasEmptyDownstream() {
        Finding finding = Finding.builder()
                .id("f6")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Something innocuous")
                .description("Nothing to see here.")
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.downstream()).isEmpty();
    }

    @Test
    void tokenKeywordFlagsSecretsIndependentlyOfAuth() {
        Finding finding = Finding.builder()
                .id("f7")
                .source("fortify")
                .kind(FindingKind.SAST)
                .title("Hardcoded API token")
                .description("An API token is hardcoded in the source file.")
                .build();

        BlastRadius result = analyzer.analyze(finding);

        assertThat(result.touchesSecrets()).isTrue();
        assertThat(result.touchesAuth()).isFalse();
        assertThat(result.touchesPii()).isFalse();
        assertThat(result.internetFacing()).isFalse();
    }
}
