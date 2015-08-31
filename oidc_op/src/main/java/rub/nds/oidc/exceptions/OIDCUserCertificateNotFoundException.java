package rub.nds.oidc.exceptions;

/**
 * OpenID Connect 'User certificate not found exception'
 * 
 * @author Philipp Markert <philipp.markert@rub.de>
 */
public class OIDCUserCertificateNotFoundException extends Exception {

    /**
     * Creates a new instance of <code>OIDCClientNotFoundException</code>
     * without a detailed message.
     */
    public OIDCUserCertificateNotFoundException() {
    }

    /**
     * Constructs an instance of <code>OIDCClientNotFoundException</code> with
     * the specified detailed message.
     *
     * @param message the detailed message.
     */
    public OIDCUserCertificateNotFoundException(String message) {
        super(message);
    }
    
}
