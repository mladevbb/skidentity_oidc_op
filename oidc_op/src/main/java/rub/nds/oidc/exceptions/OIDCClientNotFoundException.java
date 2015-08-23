package rub.nds.oidc.exceptions;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class OIDCClientNotFoundException extends Exception {

    /**
     * Creates a new instance of <code>OIDCClientNotFoundException</code>
     * without detail message.
     */
    public OIDCClientNotFoundException() {
    }

    /**
     * Constructs an instance of <code>OIDCClientNotFoundException</code> with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public OIDCClientNotFoundException(String msg) {
        super(msg);
    }
}
