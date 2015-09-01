package rub.nds.oidc.oidc_op;

import com.thoughtworks.xstream.converters.reflection.AbstractReflectionConverter.UnknownFieldException;
import java.util.List;
import static junit.framework.TestCase.assertTrue;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManagerTest {
    @Rule public ExpectedException thrown= ExpectedException.none();

    public ConfigurationManagerTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of init method, of class ConfigurationManager.
     */
    @Test
    public void testInit() {
        ConfigurationManager.initialize();

        List<Client> clientDB = OIDCCache.getCfgDB().getClientDatabase();
        assertTrue(clientDB.get(0).getClient_id().equalsIgnoreCase("Ek1P6CVtW9fNIRfZEyMyCanEoFUfjcNLWuxcPVmCJrU"));
        assertTrue(clientDB.get(0).getClient_secret().equalsIgnoreCase("P1vhVxcD2BNY0kPzyrQAOcnLkrOH8A0wkRysGocU0U8"));
        assertTrue(clientDB.get(1).getName().equalsIgnoreCase("Cloud NDS Test App 2"));
    }

    /**
     * Test of init method, of class ConfigurationManager.
     */
    @Test
    public void testInitWithErrors() {
        thrown.expect( RuntimeException.class );
        thrown.expectMessage("Cannot initialize configurationManager!");
        ConfigurationManager.initialize("nonExistingFile.xml", "configDatabaseSchema.xsd");
    }
    
    /**
     * Test of init method, of class ConfigurationManager.
     */
    @Test
    public void testInitWithErrors2() {
        
        thrown.expect(RuntimeException.class);
        ConfigurationManager.initialize("configDatabase_Errors.xml", "configDatabaseSchema.xsd");
    }
    
    /**
     * Test of init method, of class ConfigurationManager.
     */
    @Test
    public void testInitWithErrors3() {
        thrown.expect( RuntimeException.class );
        ConfigurationManager.initialize("configDatabase_Errors_1.xml", "configDatabaseSchema.xsd");
    }
    
    /**
     * Test of init method, of class ConfigurationManager.
     */
    @Test
    public void testInitWithErrors4() {
        thrown.expect( RuntimeException.class );
        ConfigurationManager.initialize("configDatabase_Errors_2.xml", "configDatabaseSchema.xsd");
    }
}
