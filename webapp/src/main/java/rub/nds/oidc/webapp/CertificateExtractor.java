package rub.nds.oidc.webapp;

import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import rub.nds.oidc.exceptions.OIDCUserCertificateNotFoundException;

/**
 * Certificate extractor.
 * 
 * @author Philipp Markert <philipp.markert@rub.de>
 */
public class CertificateExtractor {

    protected CertificateExtractor() {
    }

    /**
     * Extracts the certificate from a HTTPServletRequest.
     * 
     * @param request The HTTPServletRequest of which the certificate should be extracted
     * 
     * @return The X.509 certificate which is used in the request
     * 
     * @throws OIDCUserCertificateNotFoundException If no X.509 certificat can be found in the request
     */
    protected static X509Certificate extractCertificate(HttpServletRequest request) 
            throws OIDCUserCertificateNotFoundException {
        X509Certificate[] certificateChain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (null != certificateChain && certificateChain.length > 0) {
            return certificateChain[0];
        }
        throw new OIDCUserCertificateNotFoundException("No X.509 client certificate found in request");
    }
}
