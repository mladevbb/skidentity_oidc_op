package rub.nds.oidc.oidc_op;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import java.util.Map;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class TokenCollection {

    private AccessToken accessToken;
    private RefreshToken refreshToken;
    private IDTokenClaimsSet idToken;
    private Map<String,Object> optionalParameters;

    public TokenCollection(AccessToken accessToken, IDTokenClaimsSet idToken) {
        this.accessToken = accessToken;
        this.idToken = idToken;
    }

    public TokenCollection(AccessToken accessToken, RefreshToken refreshToken, IDTokenClaimsSet idToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
    }

    public TokenCollection(AccessToken accessToken, RefreshToken refreshToken, IDTokenClaimsSet idToken, Map<String,Object> optionalParameters) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
        this.optionalParameters = optionalParameters;
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

    public Map<String, Object> getOptionalParameters() {
        return optionalParameters;
    }

    public void setOptionalParameters(Map<String, Object> optionalParameters) {
        this.optionalParameters = optionalParameters;
    }

}
