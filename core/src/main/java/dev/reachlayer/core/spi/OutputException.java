package dev.reachlayer.core.spi;

/** Thrown by an {@link OutputRenderer} when a report cannot be delivered. Never fails the build. */
public class OutputException extends Exception {

    public OutputException(String message) {
        super(message);
    }

    public OutputException(String message, Throwable cause) {
        super(message, cause);
    }
}
