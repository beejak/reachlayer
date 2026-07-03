package dev.reachlayer.core.config;

/** Output-renderer configuration shared across renderers. */
public record OutputConfig(int topN, String commentMarker) {

    public static OutputConfig defaults() {
        return new OutputConfig(5, "<!-- reachlayer:report -->");
    }
}
