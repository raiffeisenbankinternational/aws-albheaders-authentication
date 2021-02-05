package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.springframework.security.core.AuthenticationException;

public class AWSAlbHeadersAuthenticationException extends AuthenticationException {

    public AWSAlbHeadersAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public AWSAlbHeadersAuthenticationException(String msg) {
        super(msg);
    }
}
