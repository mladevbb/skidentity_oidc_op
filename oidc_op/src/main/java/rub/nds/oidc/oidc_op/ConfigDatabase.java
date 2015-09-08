package rub.nds.oidc.oidc_op;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCNotFoundInDatabaseException;

/**
 * This class manages the database configuration
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigDatabase {

    private static final Logger _log = LoggerFactory.getLogger(ConfigDatabase.class);
    private PropertyChangeSupport propertySupport = new PropertyChangeSupport(this);

    private List<Client> clientDatabase;

    /**
     * Gets the list of client objects for this database
     *
     * @return A list of client objects
     */
    public List<Client> getClientDatabase() {
        return clientDatabase;
    }

    /**
     * Sets a list of client objects for this database
     *
     * @param clientDatabase
     */
    public void setClientDatabase(List<Client> clientDatabase) {
        this.clientDatabase = clientDatabase;
    }

    /**
     * Searches for the client corresponding to the OAuth 2.0 client identifier
     * in this database
     *
     * @param client_id The client identifier
     * @return The client
     * @throws OIDCNotFoundInDatabaseException If the {@code client id} could
     * not be found in the database
     */
    public Client getClientByID(String client_id) throws OIDCNotFoundInDatabaseException {
        for (Client c : clientDatabase) {
            if (c.getClient_id().equals(client_id)) {
                return c;
            }
        }
        _log.warn("Client with ID: " + client_id + "was not found in the Database");
        throw new OIDCNotFoundInDatabaseException("Client with ID: " + client_id + " was not found in the Database");
    }

    /**
     * Adds a property change listener which listens to the database
     *
     * @param listener The property change listener to be added
     */
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        if (propertySupport == null) {
            propertySupport = new PropertyChangeSupport(this);
        }
        propertySupport.addPropertyChangeListener(listener);
    }

    /**
     * Removes a property change listener which listens to the database
     *
     * @param listener The property change listener to be removed
     */
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        propertySupport.removePropertyChangeListener(listener);
    }

}
