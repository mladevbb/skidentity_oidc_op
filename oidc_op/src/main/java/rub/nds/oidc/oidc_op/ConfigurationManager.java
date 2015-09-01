package rub.nds.oidc.oidc_op;

import com.thoughtworks.xstream.XStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;
import rub.nds.oidc.exceptions.OIDCConfigValidationException;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManager implements ServletContextListener {

    private static final Logger _log = LoggerFactory.getLogger(ConfigurationManager.class);
    private static ConfigurationManager cfgManager;
    private static String configFile = "configDatabase.xml";
    private static String schemaFile = "configDatabaseSchema.xsd";
    
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
        initialize(configFile, schemaFile);
    }

    public static void initialize(String configFile, String schemaFile) {
        try {
            OIDCCache.initialize();
            File xmlFile = new File(ConfigurationManager.class.getClassLoader().getResource(configFile).getFile());
            File xsdFile = new File(ConfigurationManager.class.getClassLoader().getResource(schemaFile).getFile());
            
            validateXMLSchema(xsdFile, xmlFile);
            
            XStream xstream = new XStream();
            xstream.setClassLoader(ConfigDatabase.class.getClassLoader());
            xstream.processAnnotations(ConfigDatabase.class);
            
            OIDCCache.setCfgDB((ConfigDatabase) xstream.fromXML(xmlFile));
        } catch (NullPointerException | OIDCConfigValidationException ex) {
            _log.error("Cannot initialize configurationManager!", ex);
            throw new RuntimeException("Cannot initialize configurationManager!", ex);
        }
    }

    public static void validateXMLSchema(File xsdPath, File xmlPath) throws OIDCConfigValidationException{
         
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(xsdPath);
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlPath));
        } catch (IOException | SAXException e) {
            _log.error("Schema validation of config file not successful!");
            throw new OIDCConfigValidationException("Schema validation of config file not successful!");
        }
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
