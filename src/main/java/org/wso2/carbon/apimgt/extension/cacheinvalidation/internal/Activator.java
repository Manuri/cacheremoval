package org.wso2.carbon.apimgt.extension.cacheinvalidation.internal;

import org.wso2.carbon.apimgt.extension.cacheinvalidation.RevokedTokenCacheEntryRemovalOauthEventListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.wso2.carbon.identity.oauth.event.OAuthEventListener;

/**
 * The bundle activator
 */
public class Activator implements BundleActivator {
    private static Log log = LogFactory.getLog(Activator.class);

    private ServiceRegistration serviceRegistration;

    /**
     * Called when a bundle is started.
     * Here a RevokedTokenCacheEntryRemovalOauthEventListener object is
     * registered as an OSGi service under OAuthEventListener interface.
     *
     * @param bundleContext Bundle context
     * @throws Exception
     */
    public void start(BundleContext bundleContext) throws Exception {
        OAuthEventListener listener = new RevokedTokenCacheEntryRemovalOauthEventListener();
        serviceRegistration = bundleContext
                .registerService(OAuthEventListener.class.getName(), listener, null);
        if (log.isDebugEnabled()) {
            log.debug("RevokedTokenCacheEntryRemovalOauthEventListener is activated");
        }
    }

    /**
     * Called when a bundle is stopped.
     * Here, the RevokedTokenCacheEntryRemovalOauthEventListener OSGi service which was registered
     * at the bundle start is unregistered.
     *
     * @param bundleContext Bundle context
     * @throws Exception
     */
    public void stop(BundleContext bundleContext) throws Exception {
        serviceRegistration.unregister();
    }
}