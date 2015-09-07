/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rub.nds.oidc.exceptions;

/**
 *
 * @author philipp
 */
public class OIDCNotFoundInDatabaseException extends Exception {

    /**
     * Creates a new instance of OIDCNotFoundInDatabaseException
     * without detail message.
     */
    public OIDCNotFoundInDatabaseException() {
    }

    /**
     * Constructs an instance of OIDCNotFoundInDatabaseException with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public OIDCNotFoundInDatabaseException(String msg) {
        super(msg);
    }
    
}
