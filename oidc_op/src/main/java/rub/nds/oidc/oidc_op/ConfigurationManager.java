/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package rub.nds.oidc.oidc_op;

/**
 *
 * @author Vladislav Mladenov<vladislav.mladenov@rub.de>
 */
public class ConfigurationManager {
    public static void init(){
        OIDCCache.initialize();
    }
}
