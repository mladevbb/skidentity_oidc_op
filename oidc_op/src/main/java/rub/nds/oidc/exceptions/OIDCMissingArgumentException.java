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
public class OIDCMissingArgumentException extends Exception {

    /**
     * Creates a new instance of OIDCMissingArgumentException
     * without detail message.
     */
    public OIDCMissingArgumentException() {
    }

    /**
     * Constructs an instance of OIDCMissingArgumentException with
     * the specified detail message.
     *
     * @param msg the detail message.
     */
    public OIDCMissingArgumentException(String msg) {
        super(msg);
    }
    
}
