package com.sample.cacheremoval.internal;

import com.sample.cacheremoval.RevokedTokenCacheEntryRemovalOauthListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.wso2.carbon.identity.oauth.event.OAuthEventListener;

public class Activator implements BundleActivator {
    private static Log log = LogFactory.getLog(Activator.class);

    private ServiceRegistration serviceRegistration;

    public void start(BundleContext bundleContext) throws Exception {
        OAuthEventListener listener = new RevokedTokenCacheEntryRemovalOauthListener();
        ServiceRegistration serviceRegistration = bundleContext.registerService(OAuthEventListener.class.getName(), listener, null);
        if (log.isDebugEnabled()) {
            log.debug("RevokedTokenCacheEntryRemovalOauthListener is activated");
        }
    }

    public void stop(BundleContext bundleContext) throws Exception {
        serviceRegistration.unregister();
    }
}