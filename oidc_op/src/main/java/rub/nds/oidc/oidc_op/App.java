package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import java.net.URISyntaxException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.TokenPair;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutionException;
import javax.xml.crypto.Data;
import net.minidev.json.JSONObject;
import org.joda.time.DateTime;

public class App {

    public static void main(String[] args) throws URISyntaxException, SerializeException, ExecutionException, JOSEException {
        URI uri = new URI("https://c2id.com/login/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State();
        Nonce nonce = new Nonce();

        AuthenticationRequest request = new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

        System.out.println(request.toQueryString());

        OIDCCache.initialize();
        JSONObject jToken = new JSONObject();
        Issuer iss = new Issuer("skidentity.com");
        Subject sub = new Subject("vladislav.mladenov@skidentity.com");
        List<Audience> audience = new ArrayList();
        audience.add(new Audience("http://sp1.com"));

        IDTokenClaimsSet claimSet = new IDTokenClaimsSet(iss, sub, audience, new Date(), new Date());
        
        // Create an HMAC-protected JWS object with some payload
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),new Payload(claimSet.toJSONObject()));

            // We need a 256-bit key for HS256 which must be pre-shared
        byte[] sharedKey = new byte[32];
        new SecureRandom().nextBytes(sharedKey);

        // Apply the HMAC to the JWS object
        jwsObject.sign(new MACSigner(sharedKey));

        // Serialise to URL-safe format
        
        
        System.out.println("ID Token" + jwsObject.serialize());

        AuthorizationCode code = new AuthorizationCode();
        System.out.println("Code" + code.getValue());

        AccessToken token = new BearerAccessToken();
        System.out.println("Token:" + token.toString());

        RefreshToken rToken = new RefreshToken();
        TokenPair tokenPair = new TokenPair(token, rToken);

        //OIDCAccessTokenResponse oidcToken = new OIDCAccessTokenResponse(token, rToken, jwsObject);

        //OIDCCache.getHandler().put(code.getValue(), token.getValue());

        System.out.println(OIDCCache.getHandler().get(code.getValue()));
        
        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(redirectURI, code, null, null, state, state, ResponseMode.QUERY);
        response.toHTTPResponse();
    }
}
