/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rub.nds.oidc.webapp;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;
import rub.nds.oidc.exceptions.OIDCMissingArgumentException;
import rub.nds.oidc.oidc_op.OIDCManager;

/**
 *
 * @author Vladislav Mladenov <vladislav.mladenov@rub.de>
 * @author Philipp Markert <philipp.markert@rub.de>
 */
@WebServlet(name = "HoKServlet")
public class HoKServlet extends HttpServlet {

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
            throws ServletException, IOException {
        try {
            request.getSession().setAttribute("hok", true);
            HTTPResponse oidc_response = OIDCManager.generateCode(request);
            ServletUtils.applyHTTPResponse(oidc_response, response);
        } catch (OIDCMissingArgumentException | OIDCNotFoundInDatabaseException | IllegalArgumentException exception) {
            _log.warn("Caught Exception in HoKServlet.processRequest(): " + exception.getMessage(), exception);
            response.setContentType("text/html;charset=UTF-8");
            try (PrintWriter out = response.getWriter()) {
                out.println("<!DOCTYPE html>");
                out.println("<html>");
                out.println("<head>");
                out.println("<title>Authentication Error</title>");
                out.println("</head>");
                out.println("<body>");
                out.println("<h1>" + exception.getMessage() + "</h1>");
                out.println("</body>");
                out.println("</html>");
            }
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
