package dev.reachlayer.core.model;

import java.util.List;

/**
 * Plain-language attack-surface context for a finding, computed heuristically by
 * {@code enrich/blastradius} over the call graph and code metadata. Never {@code null} on a
 * {@link Finding}; each flag defaults to {@code false} / empty when not evaluated, which is the
 * conservative ("we don't know it's bad") default.
 */
public record BlastRadius(
        boolean internetFacing,
        boolean touchesAuth,
        boolean touchesPii,
        boolean touchesSecrets,
        List<String> downstream) {

    public static final BlastRadius NONE = new BlastRadius(false, false, false, false, List.of());

    public BlastRadius {
        downstream = downstream == null ? List.of() : List.copyOf(downstream);
    }

    /** Short human summary, e.g. "internet-facing, touches auth". Empty string if nothing flagged. */
    public String summary() {
        List<String> flags = new java.util.ArrayList<>();
        if (internetFacing) flags.add("internet-facing");
        if (touchesAuth) flags.add("touches auth");
        if (touchesPii) flags.add("touches PII");
        if (touchesSecrets) flags.add("touches secrets");
        return String.join(", ", flags);
    }
}
