package rub.nds.oidc.oidc_op;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import static com.nimbusds.oauth2.sdk.util.URLUtils.parseParameters;
import java.util.Map;
import org.apache.struts.mock.MockPrincipal;
import org.junit.After;
import org.junit.AfterClass;
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

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateCodeWithWrongHokFlagType() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        servletRequest.getSession().setAttribute("hok", "123");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test
    public void testGenerateAuthenticationResponseAllParametersGET() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test
    public void testGenerateAuthenticationResponseAllParametersPOST() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
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
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
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
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&redirect_uri=http://cloud.nds.rub.de:8067/&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
        // try to redeem the code a second time
        authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateAuthenticationResponseWithoutRedirectUri() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateAuthenticationResponseWithoutClienID() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        String locationQuery = codeResponse.getLocation().getQuery();
        Map<String, String> queryParameters = parseParameters(locationQuery);
        String code = queryParameters.get("code");
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("GET", "/webapp/token", "code=" + code + "redirect_uri=http://cloud.nds.rub.de:8067/");
        HTTPResponse authenticationResponse = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(servletRequest));
    }

    
    private MockHttpServletRequest generateMockServletRequest(String method, String requestURI, String queryString, boolean holderOfKeyFlag) {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod(method);
        servletRequest.setLocalAddr("localhost");
        servletRequest.setLocalPort(8443);
        servletRequest.setRequestURI(requestURI);
        servletRequest.setQueryString(queryString);
        servletRequest.getSession(true).setAttribute("hok", holderOfKeyFlag);
        servletRequest.setUserPrincipal(new MockPrincipal("philippm", new String[] {"projectWorker"}));

        return servletRequest;
    }

    private MockHttpServletRequest generateMockServletRequest(String method, String requestURI, String queryString) {
        return generateMockServletRequest(method, requestURI, queryString, Boolean.FALSE);
    }

    private HTTPResponse generateHttpResponse() {
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("GET", "/webapp/auth", "redirect_uri=http://cloud.nds.rub.de:8067/&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU", Boolean.FALSE);

            return OIDCManager.generateCode(servletRequest);
        } catch (OIDCMissingArgumentException | OIDCNotFoundInDatabaseException | IllegalArgumentException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHttpResponse: " + ex.getMessage());
        }
        return null;
    }
}
