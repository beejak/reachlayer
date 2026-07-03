package dev.reachlayer.core.spi;

/** Thrown by a {@link ScannerConnector} when a scanner export cannot be parsed. */
public class ConnectorException extends Exception {

    public ConnectorException(String message) {
        super(message);
    }

    public ConnectorException(String message, Throwable cause) {
        super(message, cause);
    }
}
