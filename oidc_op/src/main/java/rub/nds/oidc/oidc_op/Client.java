package rub.nds.oidc.oidc_op;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamImplicit;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */

@XStreamAlias("client")
public class Client {
    private static final Logger _log = LoggerFactory.getLogger(Client.class);
    
    private String name;
    @XStreamImplicit
    private List<String> redirect_uris;
    private String client_id;
    private String client_secret;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getRedirect_uris() {
        return redirect_uris;
    }

    public void setRedirect_uris(List<String> redirect_uris) {
        this.redirect_uris = redirect_uris;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getClient_secret() {
        return client_secret;
    }

    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }
}
