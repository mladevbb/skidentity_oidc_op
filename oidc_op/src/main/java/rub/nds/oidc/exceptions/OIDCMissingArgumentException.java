package rub.nds.oidc.exceptions;

/**
 * Missing argument exception used when a required argument is missing
 *
 * @author Philipp Markert <philipp.markert@rub.de>
 */
public class OIDCMissingArgumentException extends Exception {

    /**
     * Creates a new instance of OIDCMissingArgumentException without detail
     * message.
     */
    public OIDCMissingArgumentException() {
    }

    /**
     * Constructs an instance of OIDCMissingArgumentException with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public OIDCMissingArgumentException(String msg) {
        super(msg);
    }

}
