package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import rub.nds.oidc.exceptions.OIDCClientNotFoundException;
import rub.nds.oidc.exceptions.OIDCUserCertificateNotFoundException;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class OIDCManager {

    private static CertificateExtractor certificateExtractor;

    public static HTTPResponse generateCode(HTTPRequest request, HttpServletRequest servletRequest) throws OIDCUserCertificateNotFoundException, OIDCClientNotFoundException {

        try {
            Map<String, String> params = request.getQueryParameters();
            Client client = OIDCCache.getCfgDB().getClientByID(params.get("client_id"));
            String redirect_uri = params.get("redirect_uri");
            State state = new State(params.get("state"));

            AuthorizationCode code = new AuthorizationCode();
            TokenCollection collection = generateTokenCollection(servletRequest);
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
            String client_id = ClientAuthentication.parse(request).getClientID().toString();

            TokenCollection tCollection = OIDCCache.getHandler().get(code);
            OIDCCache.getHandler().invalidate(code);
            OIDCCache.getHandler().put(tCollection.getaToken().getValue(), tCollection);

            // Create an HMAC-protected JWS object with some payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(tCollection.getIdToken().toJSONObject()));

            // Apply the HMAC to the JWS object
            jwsObject.sign(new MACSigner(OIDCCache.getCfgDB().getClientByID(client_id).getClient_secret().getBytes()));

            // Serialise to URL-safe format
            OIDCAccessTokenResponse response = new OIDCAccessTokenResponse(tCollection.getaToken(), tCollection.getrToken(), jwsObject.serialize());
            return response.toHTTPResponse();

        } catch (JOSEException | ExecutionException | SerializeException | OIDCClientNotFoundException | ParseException ex) {
            Logger.getLogger(OIDCManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private static IDTokenClaimsSet generateIDToken(HttpServletRequest servletRequest) throws OIDCUserCertificateNotFoundException {
        certificateExtractor = new CertificateExtractor();
        X509Certificate userCertificate = certificateExtractor.extractCertificate(servletRequest);

        Issuer iss = new Issuer("skidentity.com");
        Subject sub = new Subject(servletRequest.getUserPrincipal().getName());
        List<Audience> audience = new ArrayList();
        audience.add(new Audience("http://sp1.com"));
        IDTokenClaimsSet claimSet = new IDTokenClaimsSet(iss, sub, audience, new Date(), new Date());
        claimSet.setClaim("user_cert", userCertificate);
        return claimSet;
    }

    private static TokenCollection generateTokenCollection(HttpServletRequest servletRequest) throws OIDCUserCertificateNotFoundException {

        AccessToken token = new BearerAccessToken();
        RefreshToken rToken = new RefreshToken();
        IDTokenClaimsSet claimSet = generateIDToken(servletRequest);

        return new TokenCollection(token, rToken, claimSet);
    }
}
