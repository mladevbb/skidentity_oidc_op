/* 
 * Copyright (C) 2014 Vladislav Mladenov<vladislav.mladenov@rub.de>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

/**
 * Class for caching the ID's of received OIDC Responses for 30 minutes This
 * class makes usage of the Google guava-libraries Caches IDs are stored within
 * the String tuple (ID, "Recently used!")
 *
 * @author Julian Krautwald <julian.krautwald@rub.de>
 * @author Vladislav Mladenov <vladislav.mladenov@rub.de>
 */
package rub.nds.oidc.oidc_op;

import com.google.common.cache.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class OIDCCache {

    private static final OIDCCache INSTANCE = new OIDCCache();
    private static LoadingCache<String, TokenCollection> cachedIDs;
    private static int cacheDuration = 30;
    private static final Logger _log = LoggerFactory.getLogger(OIDCCache.class);
    private static ConfigDatabase cfgDB;

    public static void setCfgDB(ConfigDatabase cfgDB) {
        OIDCCache.cfgDB = cfgDB;
    }

    public static ConfigDatabase getCfgDB() {
        return cfgDB;
    }
    

    private OIDCCache() {
    }

    /**
     *
     * @param cacheDuration
     */
    public static void setCacheDuration(int cacheDuration) {
        OIDCCache.cacheDuration = cacheDuration;
    }

    /**
     *
     */
    public static void initialize() {
        OIDCCache.cachedIDs = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(OIDCCache.cacheDuration, TimeUnit.MINUTES)
                .removalListener(
                new RemovalListener<String, TokenCollection>() {
            @Override
            public void onRemoval(RemovalNotification<String, TokenCollection> rn) {
                _log.debug("ID " + rn.getKey() + " has been removed from the cache.");
            }
        })
                .build(
                new CacheLoader<String, TokenCollection>() {
            @Override
            public TokenCollection load(String key) throws ExecutionException {
                return getElement(key);
            }
        });
    }

    /**
     *
     * @return
     */
    public static OIDCCache getInstance() {
        if (INSTANCE == null) {
            throw new RuntimeException("No singleton instance available");
        }
        return INSTANCE;
    }

    /**
     *
     * @return
     */
    public static LoadingCache<String, TokenCollection> getHandler() {
        return cachedIDs;
    }
    
    private static TokenCollection getElement (String key) throws ExecutionException{
        return cachedIDs.get(key);
    }
}
