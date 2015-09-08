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
 * The configuration manager for the database
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManager implements ServletContextListener {

    private static final Logger _log = LoggerFactory.getLogger(ConfigurationManager.class);
    private static ConfigurationManager cfgManager;
    private static final String configFile = "configDatabase.xml";
    private static final String schemaFile = "configDatabaseSchema.xsd";

    /**
     * Receives notification that the web application initialization process is
     * starting.
     *
     * @param sce the ServletContextEvent containing the ServletContext that is
     * being initialized
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        _log.info("Initialize the ConfigurationManager (all manager)");
        cfgManager = this;
        initialize();
    }

    /**
     * Receives notification that the ServletContext is about to be shut down.
     *
     * @param sce the ServletContextEvent containing the ServletContext that is
     * being destroyed
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        cfgManager = null;
    }

    /**
     * The initialize method. Calls
     * {@link ConfigurationManager#initialize(java.lang.String, java.lang.String)}
     * with static {@code configFile} and {@code schemaFile} parameters
     *
     */
    public static void initialize() {
        initialize(configFile, schemaFile);
    }

    /**
     * The initialize method. {@code configFile} is used to initialize the
     * database. {@code schemaFile} is used to validate the {@code configFile}
     *
     * @param configFile the XML file
     * @param schemaFile the XSD file
     */
    public static void initialize(String configFile, String schemaFile) {
        try {
            OIDCCache.initialize();
            File xmlFile = new File(ConfigurationManager.class.getClassLoader().getResource(configFile).getFile());
            File xsdFile = new File(ConfigurationManager.class.getClassLoader().getResource(schemaFile).getFile());

            validateXMLSchema(xsdFile, xmlFile);

            XStream xstream = new XStream();
            xstream.setClassLoader(ConfigDatabase.class.getClassLoader());
            xstream.processAnnotations(ConfigDatabase.class);

            //TODO: Fix configuration-setup so redirect_uris are added
            OIDCCache.setCfgDB((ConfigDatabase) xstream.fromXML(xmlFile));
        } catch (NullPointerException | OIDCConfigValidationException ex) {
            _log.error("Cannot initialize configurationManager!", ex);
            throw new RuntimeException("Cannot initialize configurationManager!", ex);
        }
    }

    /**
     * Validates the XML of file at {@code xmlPath} using the XSD file at
     * {@code xsdPath}
     *
     * @param xsdPath the path to the XSD file
     * @param xmlPath the path to the XML file
     * @throws OIDCConfigValidationException if the schema validation was not
     * succesful
     */
    public static void validateXMLSchema(File xsdPath, File xmlPath) throws OIDCConfigValidationException {

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

    /**
     * Adds a client to the database     
     *
     * @param name the name of the client
     * @param client_id the OAuth 2.0 client identifier of the client
     * @param client_secret the secret key of the client
     * @param redirect_uri the redirect URI of the client
     */
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
