/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package rub.nds.oidc.oidc_op;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class TokenCollection {
    private AccessToken aToken;
    private RefreshToken rToken;
    private IDTokenClaimsSet idToken;

    public TokenCollection(AccessToken aToken, IDTokenClaimsSet idToken) {
        this.aToken = aToken;
        this.idToken = idToken;
    }

    public TokenCollection(AccessToken aToken, RefreshToken rToken, IDTokenClaimsSet idToken) {
        this.aToken = aToken;
        this.rToken = rToken;
        this.idToken = idToken;
    }    
    
    public AccessToken getaToken() {
        return aToken;
    }

    public void setaToken(AccessToken aToken) {
        this.aToken = aToken;
    }

    public RefreshToken getrToken() {
        return rToken;
    }

    public void setrToken(RefreshToken rToken) {
        this.rToken = rToken;
    }

    public IDTokenClaimsSet getIdToken() {
        return idToken;
    }

    public void setIdToken(IDTokenClaimsSet idToken) {
        this.idToken = idToken;
    }
    
    
}
