package com.rbinternational.springsecurity.awsalbheadersauthentication.sample;

import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationFilter;
import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationProvider;
import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationTokenValidater;
import com.rbinternational.springsecurity.awsalbheadersauthentication.AWSAlbHeadersAuthenticationUserDetailsManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(
        securedEnabled = true
)
public class SampleConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // if EnableWebSecurity is used this could be used:
        // http.addFilterAfter(awsAlbAuthenticationFilter(), AnonymousAuthenticationFilter.class).authorizeRequests().anyRequest().hasRole("AUTH_USER");
        http.addFilterAfter(awsAlbAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                .authorizeRequests().anyRequest().permitAll();
    }

    protected AWSAlbHeadersAuthenticationFilter awsAlbAuthenticationFilter() throws Exception {
        AWSAlbHeadersAuthenticationFilter filter = new AWSAlbHeadersAuthenticationFilter("/");
        filter.setAuthenticationTokenValidater(authTokenValidater());
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(awsAlbHeadersAuthenticationProvider());
    }

    @Bean
    protected AWSAlbHeadersAuthenticationProvider awsAlbHeadersAuthenticationProvider() {
        AWSAlbHeadersAuthenticationProvider provider = new AWSAlbHeadersAuthenticationProvider();
        provider.setUserDetailsManager(awsAlbHeadersAuthenticationUserDetailsManager());
        return provider;
    }

    @Bean
    protected AWSAlbHeadersAuthenticationUserDetailsManager awsAlbHeadersAuthenticationUserDetailsManager() {
        AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl userDetailsManager
                = new AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl();
        userDetailsManager.setUserDetails(AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.userDetailsOK);
        return userDetailsManager;
    }

    protected AWSAlbHeadersAuthenticationTokenValidater authTokenValidater() {
        return token -> {};
    }
}
