package com.appleframework.security.auth.token;

import org.springframework.transaction.annotation.Transactional;

import com.appleframework.security.core.token.AccessToken;
import com.appleframework.security.core.token.TokenSync;
import com.appleframework.security.core.auth.Authentication;
import com.appleframework.security.core.exception.AuthenticationException;
import com.appleframework.security.core.token.RefreshToken;

/**
 * 
 * 
 * @author Cruise.Xu
 */
@Transactional
public class DefaultTokenSync implements TokenSync {

	private TokenStore tokenStore;
	
	@Override
	public void syncAccessToken(AccessToken accessToken, Authentication authentication) throws AuthenticationException {
		AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
		if (null == existingAccessToken || existingAccessToken.isExpired()) {
			tokenStore.storeAccessToken(accessToken, authentication);
			RefreshToken refreshToken = accessToken.getRefreshToken();
			if (refreshToken != null) {
				tokenStore.storeRefreshToken(refreshToken, authentication);
			}
		}
	}
	
}
