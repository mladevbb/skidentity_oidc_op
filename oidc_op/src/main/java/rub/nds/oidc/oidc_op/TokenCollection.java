package rub.nds.oidc.oidc_op;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class TokenCollection {

    private AccessToken accessToken;
    private RefreshToken refreshToken;
    private IDTokenClaimsSet idToken;

    public TokenCollection(AccessToken accessToken, IDTokenClaimsSet idToken) {
        this.accessToken = accessToken;
        this.idToken = idToken;
    }

    public TokenCollection(AccessToken accessToken, RefreshToken refreshToken, IDTokenClaimsSet idToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public IDTokenClaimsSet getIdToken() {
        return idToken;
    }

    public void setIdToken(IDTokenClaimsSet idToken) {
        this.idToken = idToken;
    }

}
