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
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;
import rub.nds.oidc.exceptions.OIDCMissingArgumentException;

/**
 *
 * @author Vladislav Mladenov <vladislav.mladenov@rub.de>
 * @author Philipp Markert <philipp.markert@rub.de>
 *
 * TODO[PM] : Kommentare, JUnit Tests
 *
 */
public class OIDCManager {

    private static final org.slf4j.Logger _log = LoggerFactory.getLogger(OIDCManager.class);
    private static String client_id;
    private static String redirect_uri;
    private static String state;

    /**
     *
     * @param request
     * @param servletRequest
     * @return
     * @throws rub.nds.oidc.exceptions.OIDCMissingArgumentException
     * @throws rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException
     */
    public static HTTPResponse generateCode(HTTPRequest request, HttpServletRequest servletRequest)
            throws OIDCMissingArgumentException, OIDCNotFoundInDatabaseException, IllegalArgumentException {

        //TODO[PM]: Empty OAuth/OIDC parameters
        try {
            Map<String, String> params = request.getQueryParameters();

            client_id = params.get("client_id");
            checkIfEmpty(client_id, "Client ID");
            Client client = OIDCCache.getCfgDB().getClientByID(client_id);

            redirect_uri = params.get("redirect_uri");
            checkIfEmpty(redirect_uri, "Redirect URI");
            if (!client.getRedirect_uris().contains(redirect_uri)) {
                _log.warn("Redirect URI was not found in database");
                //throw new OIDCNotFoundInDatabaseException("Redirect URI was not found in database");
            }

            state = params.get("state");
            checkIfEmpty(state, "State");
            State stateInstance = new State(state);

            AuthorizationCode code = new AuthorizationCode();
            TokenCollection collection = generateTokenCollection(servletRequest);
            OIDCCache.getHandler().put(code.getValue(), collection);

            AuthenticationSuccessResponse response
                    = new AuthenticationSuccessResponse(new URI(redirect_uri), code, null, null, stateInstance, stateInstance, ResponseMode.QUERY);
            return response.toHTTPResponse();
        } catch (URISyntaxException | SerializeException ex) {
            _log.warn("Caught Exception in HTTPResponse.generateCode(): ", ex);
            return null;
        }
    }

    private static void checkIfEmpty(String doubtfulString, String parameterName) throws OIDCMissingArgumentException {
        if (doubtfulString == null || doubtfulString.isEmpty()) {
            _log.warn("Parameter " + parameterName + " was not found in request");
            throw new OIDCMissingArgumentException("Parameter " + parameterName + " was not found in request");
        }
    }

    /**
     *
     * @param request
     * @return TODO [PM]: Check Signature creation and verification
     */
    public static HTTPResponse generateAuthenticationResponse(HTTPRequest request) {
        try {
            Map<String, String> params = request.getQueryParameters();
            String code = params.get("code");
            redirect_uri = params.get("redirect_uri");

            if (request.getMethod() == HTTPRequest.Method.POST || request.getMethod() == HTTPRequest.Method.PUT) {
                // parse() returns null for HTTP GET method
                client_id = ClientAuthentication.parse(request).getClientID().toString();
            } else {
                client_id = params.get("client_id");
            }

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

        } catch (JOSEException | ExecutionException | SerializeException | OIDCNotFoundInDatabaseException | ParseException ex) {
            Logger.getLogger(OIDCManager.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private static IDTokenClaimsSet generateIDToken(HttpServletRequest servletRequest) throws OIDCMissingArgumentException {

        //TODO[PM&VM]: Issuer? Issuer Identifier for the Issuer of the response. 
        // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and 
        // path components and no query or fragment components.
        Issuer iss = new Issuer("skidentity.com");

        //TODO[PM]: Exception Handling
        Subject sub = new Subject(servletRequest.getUserPrincipal().getName());

        List<Audience> audience = new ArrayList();
        audience.add(new Audience(client_id));
        IDTokenClaimsSet claimSet = new IDTokenClaimsSet(iss, sub, audience, new Date(), new Date());

        checkHokAuth(servletRequest, claimSet);

        return claimSet;
    }

    private static void checkHokAuth(HttpServletRequest servletRequest, IDTokenClaimsSet claimSet) throws OIDCMissingArgumentException {
        //TODO [PM]: Exception Handling: Variable Type
        if ((boolean) servletRequest.getSession().getAttribute("hok")) {
            CertificateExtractor certificateExtractor;

            certificateExtractor = new CertificateExtractor();
            X509Certificate userCertificate = certificateExtractor.extractCertificate(servletRequest);
            claimSet.setClaim("user_cert", userCertificate);
        }
    }

    private static TokenCollection generateTokenCollection(HttpServletRequest servletRequest) throws OIDCMissingArgumentException {
        AccessToken token = new BearerAccessToken();
        RefreshToken rToken = new RefreshToken();
        IDTokenClaimsSet claimSet = generateIDToken(servletRequest);

        return new TokenCollection(token, rToken, claimSet);
    }
}
