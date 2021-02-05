package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.springframework.security.core.AuthenticationException;

/**
 * Abstracts the validation logic for the {@link AWSAlbHeadersAuthenticationToken} validation. Normally the Jwt
 * validation logic should be plugged in here.
 */
public interface AWSAlbHeadersAuthenticationTokenValidater {

    void validate(AWSAlbHeadersAuthenticationToken token) throws AuthenticationException;
}
