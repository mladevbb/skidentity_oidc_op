package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import static com.nimbusds.oauth2.sdk.util.URLUtils.parseParameters;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Map;
import java.security.cert.X509Certificate;
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

    public OIDCManagerTest() {
    }

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

    @Test
    public void testGenerateCodeAllParameters() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeEmptyRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeMissingRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeEmptyState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeMissingState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeEmptyClientID() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeMissingClientID() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCNotFoundInDatabaseException.class)
    public void testGenerateCodeWrongClientID() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=123");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateCodeWithWrongHokFlagType() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        servletRequest.getSession().setAttribute("hok", "123");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test
    public void testGenerateAuthenticationResponseAllParametersGET() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test
    public void testGenerateAuthenticationResponseAllParametersPOST() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("POST", "/webapp/token", "");

        // Add BasicAuthentication parameters
        String clientID = "Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU";
        String clientSecret = "P1vhVxcD2BNY0kPzyrQAOcnLkrOH8A0wkRysGocU0U8";
        servletRequest.addHeader("Authorization", "Basic " + Base64.encode(clientID) + ":" + Base64.encode(clientSecret));
        // Add content
        String contentString = "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/";
        byte[] contentByte = contentString.getBytes();
        servletRequest.setContent(contentByte);

        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateAuthenticationResponseWithoutCode() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateAuthenticationResponseForgedCode() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=123&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateAuthenticationResponseMultipleCodeUsage() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        // try to redeem the code a second time
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateAuthenticationResponseWithoutRedirectUri() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateAuthenticationResponseWithoutClienID() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        Map<String, String> locationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = locationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "redirect_uri=http://cloud.nds.rub.de:8067/");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test
    public void testGenerateAuthenticationResponseHolderOfKey() throws Exception {
        X509Certificate userCertificate = importX509Certificate("/home/philipp/universitaet/6.Semester/bachelorarbeit/code/skidentity_oidc_op/certificates/user/userSelfSigned.pem");
        HTTPResponse codeResponse = generateHokHttpResponse(userCertificate);
        Map<String, String> codeResponseLocationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = codeResponseLocationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        JWT idToken = OIDCAccessTokenResponse.parse(authenticationResponse).getIDToken();
        String extractedCertificate = idToken.getJWTClaimsSet().getStringClaim("user_cert");
        Base64 base64EncodeUserCertificate = Base64.encode(userCertificate.toString());
        Assert.assertEquals(extractedCertificate, base64EncodeUserCertificate.toString());
    }

    @Test
    public void testGenerateAuthenticationResponseHolderOfKeyAttack() throws Exception {
        X509Certificate userCertificate = importX509Certificate("/home/philipp/universitaet/6.Semester/bachelorarbeit/code/skidentity_oidc_op/certificates/user/userSelfSigned.pem");
        HTTPResponse codeResponse = generateHokHttpResponse(userCertificate);
        Map<String, String> codeResponseLocationQueryParameters = getLocationQueryParameters(codeResponse);
        String code = codeResponseLocationQueryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        JWT idToken = OIDCAccessTokenResponse.parse(authenticationResponse).getIDToken();
        String extractedCertificate = idToken.getJWTClaimsSet().getStringClaim("user_cert");
        X509Certificate attackerCertificate = importX509Certificate("/home/philipp/universitaet/6.Semester/bachelorarbeit/code/skidentity_oidc_op/certificates/user/attacker.pem");
        Base64 base64EncodeCertificate = Base64.encode(attackerCertificate.toString());
        Assert.assertNotEquals(extractedCertificate, base64EncodeCertificate.toString());
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeHolderOfKeyWithoutClientCertificate() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        servletRequest.getSession().setAttribute("hok", Boolean.TRUE);
        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

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

    private MockHttpServletRequest generateMockServletRequest(String method, String requestURI, String queryString) {
        return generateMockServletRequest(method, requestURI, queryString, Boolean.FALSE);
    }

    private HTTPResponse generateHttpResponse() throws OIDCNotFoundInDatabaseException, OIDCMissingArgumentException {
        HTTPResponse codeResponse = null;
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU", Boolean.FALSE);

            codeResponse = OIDCManager.generateCode(servletRequest);
        } catch (IllegalArgumentException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHttpResponse(): " + ex.getMessage());
        }
        return codeResponse;
    }

    private HTTPResponse generateHokHttpResponse(X509Certificate certificate) throws OIDCMissingArgumentException, OIDCNotFoundInDatabaseException {
        HTTPResponse codeResponse = null;
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
            servletRequest.getSession().setAttribute("hok", Boolean.TRUE);
            X509Certificate[] certificateChain = {certificate};
            servletRequest.setAttribute("javax.servlet.request.X509Certificate", certificateChain);
            codeResponse = OIDCManager.generateCode(servletRequest);
        } catch (IllegalArgumentException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHokHttpResponse(): " + ex.getMessage());
        }
        return codeResponse;
    }

    private X509Certificate importX509Certificate(String filename) {
        X509Certificate cert = null;
        InputStream inStream = null;
        try {
            try {
                inStream = new FileInputStream(filename);
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

    private Map<String, String> getLocationQueryParameters(HTTPResponse response) {
        String locationQuery = response.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        return queryParameters;
    }
}
