package dev.reachlayer.reach.signatures;

import static org.assertj.core.api.Assertions.assertThat;

import dev.reachlayer.core.model.Component;
import dev.reachlayer.core.spi.MethodSignature;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ComponentLevelSignatureSourceTest {

    private final ComponentLevelSignatureSource source = new ComponentLevelSignatureSource();

    @Test
    void fallsBackToComponentLevelWildcardForUnknownComponents() {
        Component component = Component.of("some-random-library", "1.0.0");

        Set<MethodSignature> result = source.vulnerableMethods(component, "CVE-2099-00001");

        assertThat(result).containsExactly(MethodSignature.anyMethodOf("some-random-library"));
        assertThat(result.iterator().next().isWildcard()).isTrue();
    }

    @Test
    void returnsFineGrainedSignatureForKnownLog4ShellCve() {
        Component component = Component.of("log4j-core", "2.14.1");

        Set<MethodSignature> result = source.vulnerableMethods(component, "CVE-2021-44228");

        assertThat(result)
                .containsExactly(new MethodSignature("org.apache.logging.log4j.core.lookup.JndiLookup", "lookup"));
    }

    @Test
    void fallsBackToWildcardWhenCveDoesNotMatchKnownTable() {
        Component component = Component.of("log4j-core", "2.14.1");

        Set<MethodSignature> result = source.vulnerableMethods(component, "CVE-9999-99999");

        assertThat(result).containsExactly(MethodSignature.anyMethodOf("log4j-core"));
    }

    @Test
    void fallsBackToWildcardWhenCveIsNull() {
        Component component = Component.of("log4j-core", "2.14.1");

        Set<MethodSignature> result = source.vulnerableMethods(component, null);

        assertThat(result).containsExactly(MethodSignature.anyMethodOf("log4j-core"));
    }

    @Test
    void returnsEmptyForNullComponent() {
        assertThat(source.vulnerableMethods(null, "CVE-2021-44228")).isEmpty();
    }

    @Test
    void nameIsStable() {
        assertThat(source.name()).isEqualTo("component-level");
    }
}
