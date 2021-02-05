package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * The {@link AuthenticationProvider} implementing the authentication logic. It uses {@link AWSAlbHeadersAuthenticationUserDetailsManager} to
 * implement any logic for storing the user into some application specific backend. Most importantly, it must load the
 * application specific roles from this backend, which will be set then as {@link org.springframework.security.core.GrantedAuthority}s
 * for the resulting {@link Authentication} returned.
 */
public class AWSAlbHeadersAuthenticationProvider implements AuthenticationProvider, InitializingBean, Ordered {

    private final Logger logger = LoggerFactory.getLogger(AWSAlbHeadersAuthenticationProvider.class);

    private AWSAlbHeadersAuthenticationUserDetailsManager userDetailsManager = null;

    private int order = -1;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsManager, "A UserDetailsManager must be set");
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    public void setOrder(int i) {
        this.order = i;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException, AWSAlbHeadersAuthenticationUserDetailsManagerException {
        if (!supports(authentication.getClass())) {
            this.logger.error("Unsupported authentication class passed for {}", authentication);
            throw new AWSAlbHeadersAuthenticationException("Unsupported authentication!");
        }
        UserDetails userDetails;
        try {
            this.logger.debug("Using {}", authentication);
            AWSAlbHeadersAuthenticationToken awsAlbHeadersAuthentication = (AWSAlbHeadersAuthenticationToken) authentication;
            userDetails = this.userDetailsManager.loadUserDetails(awsAlbHeadersAuthentication);
            if (userDetails == null) {
                userDetails = this.userDetailsManager.createUser(awsAlbHeadersAuthentication);
            } else {
                userDetails = this.userDetailsManager.updateUser(awsAlbHeadersAuthentication);
            }
        }
        catch (AWSAlbHeadersAuthenticationUserDetailsManagerException e) {
            this.logger.error("Runtime exception from UserDetailsManager operation", e);
            throw e;
        }
        this.logger.debug("Got userDetails: {}", userDetails);
        AWSAlbHeadersAuthenticationToken authResult
                = new AWSAlbHeadersAuthenticationToken(userDetails, "NA", userDetails.getAuthorities());
        authResult.setAuthenticated(true);
        authResult.setDetails(authentication.getDetails());
        this.logger.debug("Created authentication obj from provider: {}", authResult);
        return authResult;
    }

    /**
     *
     * @param authentication
     *
     * @return the provided authentication class must be assignable to {@link AWSAlbHeadersAuthenticationToken}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return AWSAlbHeadersAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setUserDetailsManager(AWSAlbHeadersAuthenticationUserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }
}
