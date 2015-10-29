package com.appleframework.security.core.token;

import com.appleframework.security.core.token.AccessToken;
import com.appleframework.security.core.auth.Authentication;
import com.appleframework.security.core.exception.AuthenticationException;

/**
 * @author Cruise.Xu
 */
public interface TokenSync {
	
	void syncAccessToken(AccessToken accessToken, Authentication authentication) throws AuthenticationException;

}