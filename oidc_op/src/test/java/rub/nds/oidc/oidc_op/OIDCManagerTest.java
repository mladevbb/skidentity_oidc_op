package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import static com.nimbusds.oauth2.sdk.util.URLUtils.parseParameters;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Map;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.apache.struts.mock.MockPrincipal;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import rub.nds.oidc.exceptions.OIDCMissingArgumentException;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;

/**
 * Test class for OIDCManager
 *
 * @author Philipp Markert <philipp.markert@rub.de>
 */
public class OIDCManagerTest {

    private static final org.slf4j.Logger _log = LoggerFactory.getLogger(OIDCManager.class);
    String scope = "scope=openid";
    String redirect_uriQuery = "redirect_uri=http://cloud.nds.rub.de:8067/";
    String stateQuery = "state=1909";
    String client_idQuery = "client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU";
    HTTPResponse codeResponse, authenticationResponse;

    public OIDCManagerTest() {
    }

    /**
     * Initialize database so the client data is available
     */
    @BeforeClass
    public static void setUpClass() {
        ConfigurationManager.initialize();
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test OIDCManager.generateCode() with compliant request. All required
     * parameters are provided
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeAllParameters() throws Exception {
        codeResponse = generateCodeResponse();
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertFalse(locationParameters.get("code").isEmpty());
    }

    /**
     * Test OIDCManager.generateCode() with empty {@code scope}. The
     * {@code scope} parameter contains an empty string
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeEmptyScope() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "scope=&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_scope", locationParameters.get("error"));
        Assert.assertEquals("Parameter scope was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() without {@code scope}. No {@code scope}
     * parameter is transmitted at all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeMissingScope() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_scope", locationParameters.get("error"));
        Assert.assertEquals("Parameter scope was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() with a {@code scope} that does not
     * contain the substring 'openid'.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeWrongScope() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "scope=open&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_scope", locationParameters.get("error"));
        Assert.assertEquals("Scope does not contain 'openid'", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() with empty {@code redirect_uri}. The
     * {@code redirect_uri} parameter contains an empty string
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeEmptyRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + "redirect_uri=&" + stateQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Parameter Redirect URI was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() without {@code redirect_uri}. No
     * {@code redirect_uri} parameter is transmitted at all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeMissingRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + stateQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Parameter Redirect URI was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() with empty {@code state}. The
     * {@code state} parameter contains an empty string
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeEmptyState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&state=&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertFalse(locationParameters.get("code").isEmpty());
    }

    /**
     * Test OIDCManager.generateCode() without {@code state}. No {@code state}
     * parameter is transmitted at all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeMissingState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + client_idQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertFalse(locationParameters.get("code").isEmpty());
    }

    /**
     * Test OIDCManager.generateCode() with empty {@code client_id}. The
     * {@code client_id} parameter contains an empty string
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeEmptyClientID() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&client_id=");

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Parameter Client ID was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() without {@code client_id}. No
     * {@code client_id} parameter is transmitted at all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeMissingClientID() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Parameter Client ID was not found in request", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() with wrong {@code client_id}. The
     * transmitted {@code client_id} does not belong to a registered client
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeWrongClientID() throws Exception {
        int clientID = 123;
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&client_id=" + clientID);

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Client with ID: " + clientID + " was not found in the Database", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateCode() with invalid holder-of-key attribute
     * type. The holder-of-key attribute {@code hok} should either be set to
     * {@code true} or {@code false}. In this case an invalid value is
     * transmitted
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeWithInvalidHokFlagType() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("GET", "/webapp/auth/hok", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery);
        servletRequest.getSession().setAttribute("hok", "123");

        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
        Assert.assertEquals("Illegal argument found for attribute 'hok'", locationParameters.get("error_description"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with compliant HTTP GET
     * request. At first a {@code code} is generated. Afterwards all required
     * parameters are provided in an HTTP GET request.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseAllParametersGET() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");

        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with compliant HTTP
     * POST request. At first a {@code code} is generated. Afterwards all
     * required parameters are provided in an HTTP POST request.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseAllParametersPOST() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");

        MockHttpServletRequest servletRequest
                = generateMockServletRequest("POST", "/webapp/token", "");
        // Add Basic Authentication parameters
        String clientID = "Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU";
        String clientSecret = "P1vhVxcD2BNY0kPzyrQAOcnLkrOH8A0wkRysGocU0U8";
        servletRequest.addHeader("Authorization", "Basic " + Base64.encode(clientID + ":" +clientSecret));
        // Add content
        String contentString = "code=" + code + "&" + redirect_uriQuery;
        byte[] contentByte = contentString.getBytes();
        servletRequest.setContent(contentByte);

        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() without a {@code code}.
     * Try to get tokens without a {@code code}
     * expected
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseWithoutCode() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_grant"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with a forged or expired
     * {@code code}. Both scenarious are identical because the code is not found
     * in the database
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseForgedCode() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=123&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_grant"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with a {@code code}
     * that has already been used. Try to get reedem a {@code code} two times
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseMultipleCodeUsage() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_grant"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with missing
     * {@code redirect_uri}. No {@code redirect_uri} parameter is transmitted at
     * all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseWithoutRedirectUri() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_request"));
    }
    
    /**
     * Test OIDCManager.generateAuthenticationResponse() with wrong
     * {@code redirect_uri}. Use a different {@code redirect_uri} for the 
     * token request
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseWithDifferentRedirectUri() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + client_idQuery 
                        + "&redirect_uri=http://cloud.nds.rub.de:8067");
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_request"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with missing
     * {@code client_id}. No {@code client_id} parameter is transmitted at all
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseWithoutClienID() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_request"));
    }

    /**
     * Test OIDCManager.generateAuthenticationResponse() with a
     * {@code client_id} which is existing in the database but has not been used
     * in the code request. At first a {@code code} is generated. Afterwards
     * another exisiting {@code client_id} is provided in an HTTP GET request
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseWithWrongClientID() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");

        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&client_id=XKzid9EjileQF9AmyKFk7bXuccN_B6RmRJLqMVH9txI");
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        Assert.assertTrue(authenticationResponse.getContent().contains("invalid_grant"));
    }

    /**
     * Test the holder-of-key function. 
     * 1. A valid {@code code} is generated using holder-of-key 
     * 2. Exchange the {@code code} for the tokens (Access/ID/Refresh token) 
     * 3. Validate the ID token 
     * 4. Extract the certificate from the ID token 
     * 5. Compare both certificates
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseHolderOfKey() throws Exception {
        X509Certificate userCertificate
                = importX509Certificate("userSelfSigned.pem");
        codeResponse = generateHokHttpResponse(userCertificate);

        Map<String, String> codeResponseLocationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = codeResponseLocationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));

        Assert.assertTrue(validateIdToken(authenticationResponse));

        JWT idToken = OIDCAccessTokenResponse.parse(authenticationResponse).getIDToken();
        String extractedCertificate = idToken.getJWTClaimsSet().getStringClaim("user_cert");

        Assert.assertEquals(extractedCertificate, Base64.encode(userCertificate.toString()).toString());
    }

    /**
     * Try to circumvent the holder-of-key function. 
     * 1. A valid {@code code} is generated using holder-of-key 
     * 2. Exchange the {@code code} for the tokens (Access/ID/Refresh token) 
     * 3. Validate the ID token 
     * 4. Extract the certificate from the ID token 
     * 5. Introduce an attacker certificate 
     * 6. Compare the extracted certificate with the one from the attacker
     *
     * @throws Exception
     */
    @Test
    public void testGenerateAuthenticationResponseHolderOfKeyAttack() throws Exception {
        X509Certificate userCertificate = importX509Certificate("userSelfSigned.pem");
        codeResponse = generateHokHttpResponse(userCertificate);

        Map<String, String> codeResponseLocationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = codeResponseLocationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));

        Assert.assertTrue(validateIdToken(authenticationResponse));

        JWT idToken = OIDCAccessTokenResponse.parse(authenticationResponse).getIDToken();
        String extractedCertificate = idToken.getJWTClaimsSet().getStringClaim("user_cert");

        X509Certificate attackerCertificate
                = importX509Certificate("attacker.pem");

        Assert.assertNotEquals(extractedCertificate, Base64.encode(attackerCertificate.toString()).toString());
    }

    /**
     * Try to use holder-of-key without a certificate. Indicate that
     * holder-of-key should be used, but do not provide a certificate
     *
     * @throws Exception
     */
    @Test
    public void testGenerateCodeHolderOfKeyWithoutClientCertificate() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery);
        servletRequest.getSession().setAttribute("hok", Boolean.TRUE);
        codeResponse = OIDCManager.generateCode(servletRequest);
        Map <String, String> locationParameters = getLocationQueryParameters(codeResponse);
        Assert.assertEquals("invalid_request", locationParameters.get("error"));
    }

    /**
     * Test OIDCManager.accessProtectedResources() with valid access token. 
     * At first an {@code access_token} is generated which is then used to 
     * access a protected resource.
     *
     * @throws Exception
     */
    @Test
    public void testAccessProtectedResources() throws Exception {
        codeResponse = generateCodeResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");

        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&" + redirect_uriQuery + "&" + client_idQuery);
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        
        BearerAccessToken accessToken = OIDCAccessTokenResponse.parse(authenticationResponse).getBearerAccessToken();
        HTTPResponse response = OIDCManager.accessProtectedResource(accessToken);
        Assert.assertEquals(200, response.getStatusCode());
    }

    /**
     * Test OIDCManager.accessProtectedResources() with an invalid access token.
     *
     * @throws Exception
     */
    @Test
    public void testAccessProtectedResourcesWithInvalidAccessToken() throws Exception {
        HTTPResponse response = OIDCManager.accessProtectedResource(new BearerAccessToken("123"));
        Assert.assertEquals(400, response.getStatusCode());
    }
    
    
    
    /**
     * Generate a mock HTTP servlet request
     *
     * @param method the HTTP method
     * @param requestURI the request URI
     * @param queryString the query string (with parameters)
     * @param holderOfKeyFlag indicates if holder-of-key is requested
     * @return a mock HTTP servlet request with the transmitted parameters
     */
    private MockHttpServletRequest generateMockServletRequest(String method, String requestURI, String queryString, boolean holderOfKeyFlag) {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod(method);
        servletRequest.setLocalAddr("localhost");
        servletRequest.setLocalPort(8443);
        servletRequest.setRequestURI(requestURI);
        servletRequest.setQueryString(queryString);
        servletRequest.getSession(true).setAttribute("hok", holderOfKeyFlag);
        servletRequest.setUserPrincipal(new MockPrincipal("philippm", new String[]{"projectWorker"}));

        return servletRequest;
    }

    /**
     * Generates a mock HTTP servlet request with the hok flag set to
     * {@code false}
     *
     * @param method the HTTP method
     * @param requestURI the request URI
     * @param queryString the query string (with parameters)
     * @return a mock HTTP servlet request with the transmitted parameters
     */
    private MockHttpServletRequest generateMockServletRequest(String method, String requestURI, String queryString) {
        return generateMockServletRequest(method, requestURI, queryString, Boolean.FALSE);
    }

    /**
     * Generates a code response without holder-of-key. All required parameters
     * are provided with valid values.
     *
     * @return A code response
     * @throws OIDCNotFoundInDatabaseException
     * @throws OIDCMissingArgumentException
     */
    private HTTPResponse generateCodeResponse() throws OIDCNotFoundInDatabaseException, OIDCMissingArgumentException {
        codeResponse = null;
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery, Boolean.FALSE);

            codeResponse = OIDCManager.generateCode(servletRequest);
        } catch (IllegalArgumentException | SerializeException | IOException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHttpResponse(): " + ex.getMessage());
        }
        return codeResponse;
    }

    /**
     * Generates a code response with holder-of-key. All required parameters -
     * except the certificate - are provided with valid values.
     *
     * @param certificate the certificate to be used for holder-of-key
     * @return A code response
     * @throws OIDCMissingArgumentException
     * @throws OIDCNotFoundInDatabaseException
     */
    private HTTPResponse generateHokHttpResponse(X509Certificate certificate) throws OIDCMissingArgumentException, OIDCNotFoundInDatabaseException {
        codeResponse = null;
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("GET", "/webapp/auth", scope + "&" + redirect_uriQuery + "&" + stateQuery + "&" + client_idQuery, Boolean.TRUE);
            /**
             * A certificate chain is expected by the servlet. In this case we
             * have not got a real chain since we use a self-signed certificate.
             */
            X509Certificate[] certificateChain = {certificate};
            servletRequest.setAttribute("javax.servlet.request.X509Certificate", certificateChain);
            codeResponse = OIDCManager.generateCode(servletRequest);
        } catch (IllegalArgumentException | SerializeException | IOException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHokHttpResponse(): " + ex.getMessage());
        }
        return codeResponse;
    }

    /**
     * Imports a certificate from a specified file.
     *
     * @param filename path to the certificate
     * @return An X509Certificate
     */
    private X509Certificate importX509Certificate(String filename) {
        X509Certificate cert = null;
        InputStream inStream = null;
        try {
            try {
                inStream = new FileInputStream("src/test/resources/" + filename);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(inStream);
            } finally {
                if (inStream != null) {
                    inStream.close();
                }
            }
        } catch (CertificateException | IOException ex) {
            _log.warn("Caught exception in OIDCManagerTest.importCertificate(): " + ex.getMessage());
        }
        return cert;
    }

    /**
     * Extracts the query parameters from the location of a HTTP response
     *
     * @param response the HTTP response
     * @return the query parameters of the location
     */
    private Map<String, String> getLocationQueryParameters(HTTPResponse response) {
        String locationQuery = response.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        return queryParameters;
    }

    /**
     * Validates an ID token by means of the steps from the OpenID Connect 
     * standard (3.1.3.7.  ID Token Validation). Only applicable steps are 
     * considered:
     * 1. Validate the signature
     * 2. Test if the issuer Identifier for the OpenID Provider (which is 
     * typically obtained during Discovery) matches the value of the iss (issuer) 
     * Claim. 
     * 3. Test if the aud (audience) Claim contains the client_id value 
     * registered at the Issuer identified by the iss (issuer) Claim as an audience
     * 4. Test if the current time is be before the time represented by the exp Claim.
     *
     * @param authenticationResponse the response containing the ID token
     * @return {@code False} or {@code true}, depending on wether the ID token
     * is valid or not
     */
    private boolean validateIdToken(HTTPResponse authenticationResponse) {
        boolean validationResult = false;
        try {
            ReadOnlyJWTClaimsSet claimSet = OIDCAccessTokenResponse.parse(authenticationResponse).getIDToken().getJWTClaimsSet();
            if (validateIdTokenSignature(authenticationResponse)) {
                if (claimSet.getClaim("iss").equals("skidentity.com")) {
                    List<String> audienceList = (List<String>) claimSet.getClaim("aud");
                    if (audienceList.contains("Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU")) {
                        Date expirationDate = (Date) claimSet.getClaim("exp");
                        Date now = new Date(System.currentTimeMillis());
                        if (now.before(expirationDate)) {
                            validationResult = true;
                        }
                    }
                }
            }
        } catch (ParseException | java.text.ParseException ex) {
            _log.warn("Caught exception in OIDCManagerTest.validateIdToken(): " + ex.getMessage());
        }
        return validationResult;
    }

    /**
     * Validates the signature of an ID token
     *
     * @param authenticationResponse the response containing the ID token
     * @return {@code False} or {@code true}, depending on wether the signature
     * is valid or not
     */
    private boolean validateIdTokenSignature(HTTPResponse authenticationResponse1) {
        try {
            JWSObject idTokenToBeVerified = JWSObject.parse(OIDCAccessTokenResponse.parse(authenticationResponse1).getIDTokenString());
            // the client secret
            JWSVerifier verifier = new MACVerifier("P1vhVxcD2BNY0kPzyrQAOcnLkrOH8A0wkRysGocU0U8");
            return idTokenToBeVerified.verify(verifier);
        } catch (ParseException | JOSEException | java.text.ParseException ex) {
            _log.warn("Caught exception in OIDCManagerTest.validateIdTokenSignature(): " + ex.getMessage());
        }
        return false;
    }
}
