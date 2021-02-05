package com.rbinternational.springsecurity.awsalbheadersauthentication;

public class AWSAlbHeadersAuthenticationUserDetailsManagerException extends RuntimeException {

    public AWSAlbHeadersAuthenticationUserDetailsManagerException(String message) {
        super(message);
    }

    public AWSAlbHeadersAuthenticationUserDetailsManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
