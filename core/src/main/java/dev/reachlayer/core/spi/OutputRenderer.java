package dev.reachlayer.core.spi;

import dev.reachlayer.core.model.RankedReport;

/**
 * Pluggable output surface. The MVP implementation ({@code output/github-pr}) upserts a single
 * marker-tagged PR comment. Future renderers (SARIF, IDE, dashboard) implement the same
 * interface. Implementations must never throw in a way that fails the build — callers should
 * catch {@link OutputException} and log, not propagate as a process failure.
 */
public interface OutputRenderer {

    /** Short identifier, e.g. {@code "github-pr"}. */
    String name();

    void render(RankedReport report) throws OutputException;
}
