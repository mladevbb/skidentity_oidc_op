package rub.nds.oidc.oidc_op;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import java.util.List;

/**
 * Client party in the OpenID Connect protocol flow.
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
@XStreamAlias("client")
public class Client {

    private String name;
    @XStreamImplicit
    private List<String> redirect_uris;
    private String client_id;
    private String client_secret;

    /**
     * Gets the name of the client
     *
     * @return The name, {@code null} if not specified
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name for this client
     *
     * @param name The name of the client, {@code null} if not specified
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the redirect URIs for this client
     *
     * @return The redirect URIs, {@code null} if not specified
     */
    public List<String> getRedirect_uris() {
        return redirect_uris;
    }

    /**
     * Sets the redirect URIs for this client
     *
     * @param redirect_uris The name of the redirect URIs, {@code null} if not
     * specified
     */
    public void setRedirect_uris(List<String> redirect_uris) {
        this.redirect_uris = redirect_uris;
    }

    /**
     * Gets the OAuth 2.0 client identifier for this client
     *
     * @return The client identifier, {@code null} if not specified
     */
    public String getClient_id() {
        return client_id;
    }

    /**
     * Sets the OAuth 2.0 client identifier for this client
     *
     * @param client_id The client identifier, {@code null} if not specified
     */
    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    /**
     * Gets the secret key for this client
     *
     * @return The secret key, {@code null} if not specified
     */
    public String getClient_secret() {
        return client_secret;
    }

    /**
     * Sets the secret key for this client
     *
     * @param client_secret The secret key, {@code null} if not specified
     */
    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }
}
