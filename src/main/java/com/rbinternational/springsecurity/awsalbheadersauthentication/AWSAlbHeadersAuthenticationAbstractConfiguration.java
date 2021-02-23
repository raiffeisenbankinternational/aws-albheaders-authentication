package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public abstract class AWSAlbHeadersAuthenticationAbstractConfiguration extends WebSecurityConfigurerAdapter {

    protected AWSAlbHeadersAuthenticationFilter awsAlbAuthenticationFilter() throws Exception {
        AWSAlbHeadersAuthenticationFilter filter = new AWSAlbHeadersAuthenticationFilter("/");
        filter.setAuthenticationTokenValidater(authTokenValidator());
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(awsAlbHeadersAuthenticationProvider());
    }

    protected AWSAlbHeadersAuthenticationProvider awsAlbHeadersAuthenticationProvider() {
        AWSAlbHeadersAuthenticationProvider provider = new AWSAlbHeadersAuthenticationProvider();
        provider.setUserDetailsManager(awsAlbHeadersAuthenticationUserDetailsManager());
        return provider;
    }

    protected abstract AWSAlbHeadersAuthenticationUserDetailsManager awsAlbHeadersAuthenticationUserDetailsManager();

    protected abstract AWSAlbHeadersAuthenticationTokenValidator authTokenValidator();
}
