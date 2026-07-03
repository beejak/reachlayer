package dev.reachlayer.core.model;

/** Coarse category of a {@link Finding}, matching the two MVP scanner families. */
public enum FindingKind {
    SAST,
    SCA;

    public String wireValue() {
        return name().toLowerCase(java.util.Locale.ROOT);
    }
}
