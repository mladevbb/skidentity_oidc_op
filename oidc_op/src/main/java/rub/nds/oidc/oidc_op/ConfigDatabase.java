package rub.nds.oidc.oidc_op;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rub.nds.oidc.exceptions.OIDCClientNotFoundException;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigDatabase {
    private static final Logger _log = LoggerFactory.getLogger(ConfigDatabase.class);
    private PropertyChangeSupport propertySupport = new PropertyChangeSupport(this);

    private List<Client> clientDatabase;

    public List<Client> getClientDatabase() {
        return clientDatabase;
    }

    public void setClientDatabase(List<Client> clientDatabase) {
        this.clientDatabase = clientDatabase;
    }
    
    public Client getClientByID(String client_id) throws OIDCClientNotFoundException{
        for (Client c : clientDatabase){
            if (c.getClient_id().equals(client_id)){
                return c;
            }
        }
        _log.warn("Client with ID: " + client_id + "was not found in the Database");
        throw new OIDCClientNotFoundException("Client with ID: " + client_id + "was not found in the Database");
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        if (propertySupport == null) {  propertySupport = new PropertyChangeSupport(this); }
        propertySupport.addPropertyChangeListener(listener);
    }

    public void removePropertyChangeListener(PropertyChangeListener listener) {
        propertySupport.removePropertyChangeListener(listener);
    }
    
}
