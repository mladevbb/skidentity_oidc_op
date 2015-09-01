/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rub.nds.oidc.exceptions;

/**
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
