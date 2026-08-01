package dev.reachlayer.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class EntryPointOverridesTest {

    @Test
    void defaultsAreEmpty() {
        EntryPointOverrides overrides = EntryPointOverrides.defaults();

        assertThat(overrides.extraAnnotations()).isEmpty();
        assertThat(overrides.extraClasses()).isEmpty();
    }

    @Test
    void nullListsAreTreatedAsEmptyRatherThanThrowing() {
        EntryPointOverrides overrides = new EntryPointOverrides(null, null);

        assertThat(overrides.extraAnnotations()).isEmpty();
        assertThat(overrides.extraClasses()).isEmpty();
    }

    @Test
    void preservesProvidedValues() {
        EntryPointOverrides overrides =
                new EntryPointOverrides(List.of("com.example.Scheduled"), List.of("com.example.Job"));

        assertThat(overrides.extraAnnotations()).containsExactly("com.example.Scheduled");
        assertThat(overrides.extraClasses()).containsExactly("com.example.Job");
    }
}
