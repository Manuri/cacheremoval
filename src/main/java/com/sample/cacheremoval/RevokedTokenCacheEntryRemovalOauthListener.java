package com.sample.cacheremoval;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.impl.APIConstants;
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

public class RevokedTokenCacheEntryRemovalOauthListener implements OAuthEventListener {
    private Log log = LogFactory.getLog(RevokedTokenCacheEntryRemovalOauthListener.class);

    public void onPreTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

    }

    public void onPostTokenIssue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

    }

    public void onPreTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

    }

    public void onPostTokenIssue(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext, AccessTokenDO accessTokenDO,
            OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO) throws IdentityOAuth2Exception {

    }

    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

    }

    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO,
            OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO, OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

    }

    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO)
            throws IdentityOAuth2Exception {

    }

    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
            OAuthRevocationResponseDTO oAuthRevocationResponseDTO, AccessTokenDO accessTokenDO,
            RefreshTokenValidationDataDO refreshTokenValidationDataDO) throws IdentityOAuth2Exception {
        Cache keyCache = Caching.getCacheManager(APIConstants.API_MANAGER_CACHE_MANAGER).
                getCache(APIConstants.KEY_CACHE_NAME);
        for (Object entry : keyCache) {
            Cache.Entry cacheEntry = (Cache.Entry) entry;
            String cachedAccessToken = cacheEntry.getKey().toString().split(":")[0];
            if (cachedAccessToken.equals(accessTokenDO.getAccessToken())) {
                keyCache.remove(cacheEntry.getKey());
                log.info("Key Manager cache entry was removed for the access token: " + accessTokenDO.getAccessToken()
                        + " after revocation");
            }
        }
    }

    public void onPreTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO)
            throws IdentityOAuth2Exception {

    }

    public void onPostTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO oAuthRevocationRequestDTO,
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO oAuthRevocationResponseDTO,
            AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

    }

    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO)
            throws IdentityOAuth2Exception {

    }

    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
            OAuth2TokenValidationResponseDTO oAuth2TokenValidationResponseDTO) throws IdentityOAuth2Exception {

    }
}
