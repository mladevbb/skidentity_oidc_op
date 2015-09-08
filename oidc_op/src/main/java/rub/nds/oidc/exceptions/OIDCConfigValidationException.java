package rub.nds.oidc.exceptions;

/**
 * Configuration validation exception used for XML schema validation
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class OIDCConfigValidationException extends Exception {

    /**
     * Creates a new instance of <code>OIDCConfigValidationException</code>
     * without detail message.
     */
    public OIDCConfigValidationException() {
    }

    /**
     * Constructs an instance of <code>OIDCConfigValidationException</code> with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public OIDCConfigValidationException(String msg) {
        super(msg);
    }
}
