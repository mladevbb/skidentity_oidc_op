package rub.nds.oidc.oidc_op;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;
import rub.nds.oidc.exceptions.OIDCMissingArgumentException;

/**
 * Processes the OpenID Connect requests of the servlets
 *
 * @author Vladislav Mladenov <vladislav.mladenov@rub.de>
 * @author Philipp Markert <philipp.markert@rub.de>
 *
 */
public class OIDCManager {

    private static final org.slf4j.Logger _log = LoggerFactory.getLogger(OIDCManager.class);
    private static String client_id;
    private static String redirect_uri;
    private static String state;
    /**
     * Generates an HTTP response containing an OAuth 2.0 code using the
     * parameters of the {@code servletRequest}
     *
     * @param servletRequest the request of the servlet
     * @return A HTTPResponse containing an OAuth 2.0 code
     * @throws rub.nds.oidc.exceptions.OIDCMissingArgumentException If a
     * required argument is missing in the {@code servletRequest}
     * @throws rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException If a
     * transmitted parameter of the {@code servletRequest} could not be found in
     * the database
     */
    public static HTTPResponse generateCode(HttpServletRequest servletRequest)
            throws OIDCMissingArgumentException, OIDCNotFoundInDatabaseException, IllegalArgumentException, IllegalArgumentException {
        try {
            HTTPRequest request = ServletUtils.createHTTPRequest(servletRequest);
            Map<String, String> params = request.getQueryParameters();

            String scope = params.get("scope");
            checkIfEmpty(scope, "scope");
            if(!scope.contains("openid")) {
                _log.warn("Scope does not contain 'openid'");
                throw new IllegalArgumentException("Scope does not contain 'openid'");
            }
            
            
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

            // Generate a code as well as the tokens and put them in the cache
            AuthorizationCode code = new AuthorizationCode();
            TokenCollection collection = generateTokenCollection(servletRequest, client_id);
            OIDCCache.getHandler().put(code.getValue(), collection);

            AuthenticationSuccessResponse response
                    = new AuthenticationSuccessResponse(new URI(redirect_uri), code, null, null, stateInstance, stateInstance, ResponseMode.QUERY);
            return response.toHTTPResponse();
        } catch (URISyntaxException | SerializeException | IOException ex) {
            _log.warn("Caught Exception in HTTPResponse.generateCode(): ", ex);
            return null;
        }
    }

    /**
     * Generates an OpenID Connect authentication response. A code is expected
     * in the request and an ID token, an access token, and a refresh token are
     * provided in the response
     *
     * @param request an OpenID Connect authentication request
     * @return an OpenID Connect authentication response
     * @throws rub.nds.oidc.exceptions.OIDCMissingArgumentException If a
     * required argument is missing in the {@code request}
     * @throws rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException If a
     * transmitted parameter of the {@code request} could not be found in the
     * database
     */
    public static HTTPResponse generateAuthenticationResponse(HTTPRequest request)
            throws OIDCMissingArgumentException, OIDCNotFoundInDatabaseException, IllegalStateException {
        try {
            Map<String, String> params = request.getQueryParameters();

            String code = params.get("code");
            checkIfEmpty(code, "Code");

            redirect_uri = params.get("redirect_uri");
            checkIfEmpty(redirect_uri, "Redirect URI");

            // ClientID - used as the username - may be located in the HTTP Header when Basic Authentication is used.
            // Check needed because parse() returns null for HTTP GET method
            if (request.getMethod() == HTTPRequest.Method.POST || request.getMethod() == HTTPRequest.Method.PUT) {
                client_id = ClientAuthentication.parse(request).getClientID().toString();
            } else {
                client_id = params.get("client_id");
            }
            checkIfEmpty(client_id, "Client ID");
            Client client = OIDCCache.getCfgDB().getClientByID(client_id);
            // Check if code was issued to the specified client
            TokenCollection tCollection = OIDCCache.getHandler().get(code);
            if(!tCollection.getOptionalParameters().containsValue(client_id)) {
                _log.warn("Code was not issued to the specified client");
                throw new IllegalStateException("Code was not issued to the specified client");
            }
            // client_id only needed for the above verification -> remove now
            tCollection.getOptionalParameters().remove("client_id");
            
            // Invalidate the code and replace it with the corresponding access token
            OIDCCache.getHandler().invalidate(code);
            OIDCCache.getHandler().put(tCollection.getAccessToken().getValue(), tCollection);

            // Create an HMAC-protected JWS object with some payload
            JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(tCollection.getIdToken().toJSONObject()));

            // Apply the HMAC to the JWS object
            jwsObject.sign(new MACSigner(OIDCCache.getCfgDB().getClientByID(client_id).getClient_secret().getBytes()));

            // Serialise to URL-safe format
            OIDCAccessTokenResponse response = 
                    new OIDCAccessTokenResponse(tCollection.getAccessToken(), tCollection.getRefreshToken(), jwsObject.serialize(), tCollection.getOptionalParameters());
            return response.toHTTPResponse();

        } catch (JOSEException | ExecutionException | SerializeException | ParseException ex) {
            _log.warn("Caught Exception in HTTPResponse.generateAuthenticationResponse(): ", ex);
            return null;
        } catch (UncheckedExecutionException ex) {
            // OIDCache throws UncheckedExecutionException which contains an IllegalStateException
            throw new IllegalStateException(ex.getMessage().substring(32));
        }
    }

    /**
     * Generates a token collection
     *
     * @param servletRequest Forwarded to
     * {@link OIDCManager#generateIDToken(javax.servlet.http.HttpServletRequest)}
     * Only needed for holder-of-key
     * @return the token collection
     * @throws OIDCMissingArgumentException If a required argument is missing in
     * the {@code servletRequest}
     * @throws IllegalArgumentException If the parameter 'hok' in the
     * {@code servletRequest} does not contain a boolean
     */
    private static TokenCollection generateTokenCollection(HttpServletRequest servletRequest, String clientId)
            throws OIDCMissingArgumentException, IllegalArgumentException {
        AccessToken token = new BearerAccessToken();
        RefreshToken rToken = new RefreshToken();
        IDTokenClaimsSet claimSet = generateIDToken(servletRequest);
        Map<String,Object> optionalParameters = new HashMap();
        optionalParameters.put("expires_in", 1800);
        optionalParameters.put("client_id", clientId);
        
        return new TokenCollection(token, rToken, claimSet, optionalParameters);
    }

    /**
     * Generate an OpenID Connect ID token claim set
     *
     * @param servletRequest the OpenID Connect authentication request.
     * Forwarded to
     * {@link OIDCManager#checkHokAuth(javax.servlet.http.HttpServletRequest, com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet)}
     * Only needed for holder-of-key
     * @return the claim set
     * @throws OIDCMissingArgumentException If a required argument is missing in
     * the {@code servletRequest}
     * @throws IllegalArgumentException If the parameter 'hok' in the
     * {@code servletRequest} does not contain a boolean
     */
    private static IDTokenClaimsSet generateIDToken(HttpServletRequest servletRequest)
            throws OIDCMissingArgumentException, IllegalArgumentException {

        //TODO[PM&VM]: Issuer? Issuer Identifier for the Issuer of the response. 
        // The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and 
        // path components and no query or fragment components.
        Issuer iss = new Issuer("skidentity.com");

        Subject sub;
        try {
            String subjectString = servletRequest.getUserPrincipal().getName();
            checkIfEmpty(subjectString, "Subject");
            sub = new Subject(subjectString);
        } catch (NullPointerException ex) {
            String message = "No User Principal found";
            _log.warn(message);
            throw new OIDCMissingArgumentException(message);
        }

        List<Audience> audience = new ArrayList();
        audience.add(new Audience(client_id));

        Date issueDate = new Date();
        Date expirationDate = new Date(System.currentTimeMillis() + (120*1000));

        IDTokenClaimsSet claimSet = new IDTokenClaimsSet(iss, sub, audience, expirationDate, issueDate);

        checkHokAuth(servletRequest, claimSet);

        return claimSet;
    }

    private static void checkIfEmpty(String doubtfulString, String parameterName) throws OIDCMissingArgumentException {
        if (doubtfulString == null || doubtfulString.isEmpty()) {
            _log.warn("Parameter " + parameterName + " was not found in request");
            throw new OIDCMissingArgumentException("Parameter " + parameterName + " was not found in request");
        }
    }

    /**
     * Check if holder-of-key is required. If 'yes': search the
     * {@code servletRequest} for the user certificate and add it to the
     * {@code claimSet} if one is found
     *
     * @param servletRequest the servlet request
     * @param claimSet the claim set to which the user certificate is added to
     * @throws OIDCMissingArgumentException If holder-of-key is required but the
     * user certificate is missing in the {@code servletRequest}
     * @throws IllegalArgumentException If the parameter 'hok' in the
     * {@code servletRequest} does not contain a boolean
     */
    private static void checkHokAuth(HttpServletRequest servletRequest, IDTokenClaimsSet claimSet)
            throws OIDCMissingArgumentException, IllegalArgumentException {
        if (servletRequest.getSession().getAttribute("hok") instanceof Boolean) {
            if ((boolean) servletRequest.getSession().getAttribute("hok")) {
                CertificateExtractor certificateExtractor = new CertificateExtractor();
                X509Certificate userCertificate = certificateExtractor.extractCertificate(servletRequest);
                claimSet.setClaim("user_cert", Base64.encode(userCertificate.toString()));
            }
        } else {
            throw new IllegalArgumentException("Illegal argument found for attribute 'hok'");
        }
    }
}
