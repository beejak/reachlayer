package dev.reachlayer.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class SuppressionConfigTest {

    @Test
    void defaultsAreEmpty() {
        assertThat(SuppressionConfig.defaults().displayCwes()).isEmpty();
    }

    @Test
    void nullMapIsTreatedAsEmptyRatherThanThrowing() {
        assertThat(new SuppressionConfig(null).displayCwes()).isEmpty();
    }

    @Test
    void preservesProvidedValues() {
        SuppressionConfig config = new SuppressionConfig(Map.of("CWE-563", "lint noise"));

        assertThat(config.displayCwes()).containsEntry("CWE-563", "lint noise");
    }
}
