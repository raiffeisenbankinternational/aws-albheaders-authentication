package com.rbinternational.springsecurity.awsalbheadersauthentication.sample;

import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationToken;
import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationUserDetailsManager;
import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationUserDetailsManagerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl implements AWSAlbHeadersAuthenticationUserDetailsManager {

    public static final UserDetails userDetailsOK = User.withUsername("dummy").password("").authorities("ROLE_AUTH_USER").build();
    public static final UserDetails userDetails403 = User.withUsername("dummy").password("").authorities("ROLE_AUTH_USER1").build();

    private final Logger logger = LoggerFactory.getLogger(AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.class);

    private boolean throwsException = false;

    private UserDetails userDetails;

    @Override
    public UserDetails createUser(AWSAlbHeadersAuthenticationToken userDetails) throws AWSAlbHeadersAuthenticationUserDetailsManagerException {
        this.logger.info("AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.createUser: {}", this.userDetails);
        if (this.throwsException) {
            throw new AWSAlbHeadersAuthenticationUserDetailsManagerException("createUser threw an exception");
        }
        return this.userDetails;
    }

    @Override
    public UserDetails updateUser(AWSAlbHeadersAuthenticationToken userDetails) throws AWSAlbHeadersAuthenticationUserDetailsManagerException {
        this.logger.info("AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.updateUser: {}", this.userDetails);
        if (this.throwsException) {
            throw new AWSAlbHeadersAuthenticationUserDetailsManagerException("updateUser threw an exception");
        }
        return this.userDetails;
    }

    @Override
    public UserDetails loadUserDetails(AWSAlbHeadersAuthenticationToken token) throws AWSAlbHeadersAuthenticationUserDetailsManagerException {
        this.logger.info("AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.loadUserDetails: {}", token);
        if (this.throwsException) {
            throw new AWSAlbHeadersAuthenticationUserDetailsManagerException("loadUserDetails threw an exception");
        }
        return this.userDetails;
    }

    public void setUserDetails(UserDetails userDetails) {
        this.userDetails = userDetails;
    }

    public void setThrowsException(boolean throwsException) {
        this.throwsException = throwsException;
    }
}
