package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.minidev.json.JSONObject;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class OIDCManager {

    public static HTTPResponse generateCode(HTTPRequest request) {
        ConfigurationManager.init();

        try {
            Map<String, String> params = request.getQueryParameters();
            String redirect_uri = params.get("redirect_uri");
            State state = new State(params.get("state"));

            AuthorizationCode code = new AuthorizationCode();
            TokenCollection collection = generateTokenCollection();
            OIDCCache.getHandler().put(code.getValue(), collection);

            AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(new URI(redirect_uri), code, null, null, state, state, ResponseMode.QUERY);
            return response.toHTTPResponse();
        } catch (URISyntaxException | SerializeException ex) {
            Logger.getLogger(OIDCManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public static HTTPResponse generateAuthenticationResponse(HTTPRequest request) {
        try {
            Map<String, String> params = request.getQueryParameters();
            String code = params.get("code");
             String redirect_uri = params.get("redirect_uri");

            TokenCollection tCollection = OIDCCache.getHandler().get(code);
            OIDCCache.getHandler().invalidate(code);
            OIDCCache.getHandler().put(tCollection.getaToken().getValue(), tCollection);

            // Create an HMAC-protected JWS object with some payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(tCollection.getIdToken().toJSONObject()));

            // We need a 256-bit key for HS256 which must be pre-shared
            byte[] sharedKey = new byte[32];
            new SecureRandom().nextBytes(sharedKey);

            // Apply the HMAC to the JWS object
            jwsObject.sign(new MACSigner(sharedKey));

            // Serialise to URL-safe format
            OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(tCollection.getaToken(), tCollection.getrToken(), jwsObject.serialize());
            return response.toHTTPResponse();

        } catch (JOSEException | ExecutionException | SerializeException ex) {
            Logger.getLogger(OIDCManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } 
    }

    private static IDTokenClaimsSet generateIDToken() {
        JSONObject jToken = new JSONObject();
        Issuer iss = new Issuer("skidentity.com");
        Subject sub = new Subject("vladislav.mladenov@skidentity.com");
        List<Audience> audience = new ArrayList();
        audience.add(new Audience("http://sp1.com"));
        return new IDTokenClaimsSet(iss, sub, audience, new Date(), new Date());
    }

    private static TokenCollection generateTokenCollection() {

        AccessToken token = new BearerAccessToken();
        RefreshToken rToken = new RefreshToken();
        IDTokenClaimsSet claimSet = generateIDToken();

        return new TokenCollection(token, rToken, claimSet);
    }
}