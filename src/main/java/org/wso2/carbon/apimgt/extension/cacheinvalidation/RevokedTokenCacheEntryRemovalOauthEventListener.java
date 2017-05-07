package org.wso2.carbon.apimgt.extension.cacheinvalidation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.keymgt.util.APIKeyMgtDataHolder;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.event.OAuthEventListener;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import javax.cache.Cache;
import javax.cache.Caching;
import java.util.Iterator;

/**
 * This OAuthEventListener removes the access token entries from API Manager Key Manager cache
 * when an access token is revoked by a client.
 */
public class RevokedTokenCacheEntryRemovalOauthEventListener implements OAuthEventListener {
    private Log log = LogFactory.getLog(RevokedTokenCacheEntryRemovalOauthEventListener.class);

    public void onPreTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPostTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPreTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPostTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, AccessTokenDO accessTokenDO,
            OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO) throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    /**
     * This method removes the Key Manager cache entry after the access token revocation by client.
     *
     * @param oAuthRevocationRequestDTO The data Transfer Object containing oauth revocation request
     * @param oAuthRevocationResponseDTO The data Transfer Object containing oauth revocation response
     * @param accessTokenDO This contains the access token and related parameters
     * @param refreshTokenValidationDataDO The results holder for refresh token validation query
     * @throws IdentityOAuth2Exception
     */
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
            OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO,
            RefreshTokenValidationDataDO refreshTokenValidationDataDO) throws IdentityOAuth2Exception {
        if (accessTokenDO == null) {
            log.warn("Unable to remove the cache entry since access token you tried to revoke does not exist.");
            return;
        }

        if (APIKeyMgtDataHolder.getKeyCacheEnabledKeyMgt()) {
            final AccessTokenDO anAccessTokenDO = accessTokenDO;
            Thread thread = new Thread(new Runnable() {
                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext
                        .getThreadLocalCarbonContext();
                int tenantId = carbonContext.getTenantId();
                String tenantDomain = carbonContext.getTenantDomain();
                public void run() {
                    try {
                        PrivilegedCarbonContext.startTenantFlow();
                        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                        carbonContext.setTenantId(tenantId);
                        carbonContext.setTenantDomain(tenantDomain);
                        Cache keyManagerCache = Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).
                                getCache(APIConstants.KEY_CACHE_NAME);
                        Iterator<Object> iterator = keyManagerCache.iterator();
                        while (iterator.hasNext()) {
                            Cache.Entry cacheEntry = (Cache.Entry) iterator.next();
                            if (cacheEntry != null) {
                                String cachedAccessToken = cacheEntry.getKey().toString().split(":")[0];
                                if (cachedAccessToken.equals(anAccessTokenDO.getAccessToken())) {
                                    keyManagerCache.remove(cacheEntry.getKey());
                                    if (log.isDebugEnabled()) {
                                        log.debug("Key Manager cache entry was removed for the access token after "
                                                + "revocation. " + "Consumer key: " + anAccessTokenDO.getConsumerKey());
                                    }
                                }
                            }
                        }
                    } finally {
                        PrivilegedCarbonContext.endTenantFlow();
                    }
                }
            });
            thread.start();
        }
    }

    public void onPreTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPostTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO oAuthRevocationResponseDTO,
            AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO)
            throws IdentityOAuth2Exception {
        // Not implemented
    }

    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
            OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO) throws IdentityOAuth2Exception {
        // Not imlemented
    }
}
