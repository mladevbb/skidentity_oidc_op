package rub.nds.oidc.exceptions;

/**
 * Not found in database exception used when a given parameter could not be
 * found in the database
 *
 * @author Philipp Markert <philipp.markert@rub.de>
 */
public class OIDCNotFoundInDatabaseException extends Exception {

    /**
     * Creates a new instance of OIDCNotFoundInDatabaseException without detail
     * message.
     */
    public OIDCNotFoundInDatabaseException() {
    }

    /**
     * Constructs an instance of OIDCNotFoundInDatabaseException with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public OIDCNotFoundInDatabaseException(String msg) {
        super(msg);
    }

}
