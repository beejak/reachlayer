package dev.reachlayer.core.model;

/**
 * An SCA component (dependency), e.g. {@code org.apache.commons:commons-compress@1.21}.
 * {@code ecosystem} is a loose hint ("maven", "npm", ...) used by signature sources; it may be
 * {@code null} when unknown.
 */
public record Component(String name, String version, String ecosystem) {

    public Component {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Component name must not be blank");
        }
    }

    public static Component of(String name, String version) {
        return new Component(name, version, null);
    }

    /** {@code name@version}, or just {@code name} if the version is unknown. */
    public String coordinate() {
        return version == null || version.isBlank() ? name : name + "@" + version;
    }

    @Override
    public String toString() {
        return coordinate();
    }
}
