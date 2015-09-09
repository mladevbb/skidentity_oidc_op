package rub.nds.oidc.oidc_op;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
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
    public void testGenerateCodeWithoutHokAllParameters() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("redirect_uri=http://bvb.de&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokEmptyRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("redirect_uri=&state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokMissingRedirectUri() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokEmptyState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("redirect_uri=http://bvb.de&state=&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokMissingState() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("redirect_uri=http://bvb.de&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokEmptyClientID() throws Exception {
        MockHttpServletRequest servletRequest
                = generateMockServletRequest("redirect_uri=http://bvb.de&state=1909&client_id=");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test(expected = OIDCMissingArgumentException.class)
    public void testGenerateCodeWithoutHokMissingClientID() throws Exception {
        MockHttpServletRequest servletRequest = generateMockServletRequest("redirect_uri=http://bvb.de&state=1909");

        HTTPResponse result = OIDCManager.generateCode(servletRequest);
    }

    @Test
    public void testGenerateAuthenticationResponse() throws Exception {
        HTTPResponse codeResponse = generateHttpResponse();
        //String code = codeResponse.getContentAsJSONObject().get("code").toString();
        //MockServletRequest servletRequest
        //= generateMockServletRequest("state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU");
    }

    private MockHttpServletRequest generateMockServletRequest(String queryString, boolean holderOfKeyFlag) {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.setMethod("GET");
        servletRequest.setLocalAddr("localhost");
        servletRequest.setLocalPort(8443);
        servletRequest.setRequestURI("/webapp/auth");
        servletRequest.setQueryString(queryString);
        servletRequest.getSession(true).setAttribute("hok", holderOfKeyFlag);
        
        return servletRequest;
    }

    private MockHttpServletRequest generateMockServletRequest(String queryString) {
        return generateMockServletRequest(queryString, Boolean.FALSE);
    }

    private HTTPResponse generateHttpResponse() {
        try {
            MockHttpServletRequest servletRequest
                    = generateMockServletRequest("state=1909&client_id=Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU", Boolean.FALSE);

            return OIDCManager.generateCode(servletRequest);
        } catch (OIDCMissingArgumentException | OIDCNotFoundInDatabaseException | IllegalArgumentException ex) {
            _log.warn("Caught exception in OIDCManagerTest.generateHttpResponse: " + ex.getMessage());
        }
        return null;
    }
}
