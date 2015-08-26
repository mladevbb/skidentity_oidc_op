package rub.nds.oidc.oidc_op;

import java.util.List;
import junit.framework.TestCase;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManagerTest extends TestCase {

    public ConfigurationManagerTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of init method, of class ConfigurationManager.
     */
    public void testInit() {
        ConfigurationManager.initialize();

        List<Client> clientDB = OIDCCache.getCfgDB().getClientDatabase();

        for (Client c : clientDB) {
            System.out.println("Client: " + c.getName());
        }
    }

}
