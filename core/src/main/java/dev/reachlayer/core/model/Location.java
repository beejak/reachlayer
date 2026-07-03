package dev.reachlayer.core.model;

/**
 * Where a finding was reported in source. All fields are best-effort and may be {@code null}
 * (e.g. an SCA finding usually has no line number, only a component).
 */
public record Location(String file, Integer startLine, Integer endLine, String methodSignature) {

    public static Location unknown() {
        return new Location(null, null, null, null);
    }

    public static Location ofFile(String file) {
        return new Location(file, null, null, null);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (file != null) {
            sb.append(file);
        }
        if (startLine != null) {
            sb.append(':').append(startLine);
            if (endLine != null && !endLine.equals(startLine)) {
                sb.append('-').append(endLine);
            }
        }
        if (methodSignature != null) {
            if (!sb.isEmpty()) {
                sb.append(' ');
            }
            sb.append('(').append(methodSignature).append(')');
        }
        return sb.isEmpty() ? "unknown" : sb.toString();
    }
}
