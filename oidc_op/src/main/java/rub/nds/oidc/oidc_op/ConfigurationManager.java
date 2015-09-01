package rub.nds.oidc.oidc_op;

import com.thoughtworks.xstream.XStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManager implements ServletContextListener {

    private static final Logger _log = LoggerFactory.getLogger(ConfigurationManager.class);
    private static ConfigurationManager cfgManager;
    private static String configFile = "configDatabase.xml";

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        _log.info("Initialize the ConfigurationManager (all manager)");
        cfgManager = this;
        initialize();
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        cfgManager = null;
    }

    public static void initialize() {
        OIDCCache.initialize();

        XStream xstream = new XStream();
        xstream.setClassLoader(ConfigDatabase.class.getClassLoader());
        xstream.processAnnotations(ConfigDatabase.class);
        File file = new File(ConfigurationManager.class.getClassLoader().getResource(configFile).getFile());
        OIDCCache.setCfgDB((ConfigDatabase) xstream.fromXML(file));
    }

    public static void addClient(String name, String client_id, String client_secret, String redirect_uri) {
        Client client = new Client();
        client.setName(name);
        client.setClient_id(client_id);
        client.setClient_secret(client_secret);
        client.getRedirect_uris().add(redirect_uri);
        
        List<Client> clients = OIDCCache.getCfgDB().getClientDatabase();
        clients.add(client);
    }
}
