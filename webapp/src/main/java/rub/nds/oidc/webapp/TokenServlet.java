package rub.nds.oidc.webapp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.ExecutionException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCMissingArgumentException;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;
import rub.nds.oidc.oidc_op.OIDCManager;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
@WebServlet(name = "TokenServlet", urlPatterns = {"/token"})
public class TokenServlet extends HttpServlet {

    private static final org.slf4j.Logger _log = LoggerFactory.getLogger(OIDCManager.class);

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException{
        try {
            HTTPResponse oidc_response = OIDCManager.generateAuthenticationResponse(ServletUtils.createHTTPRequest(request));
            ServletUtils.applyHTTPResponse(oidc_response, response);
        } catch (ParseException | ExecutionException | JOSEException | SerializeException exception) {
            _log.warn("Caught Exception in TokenServlet.processRequest(): " + exception.getMessage(), exception);
        }
    }

// <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
