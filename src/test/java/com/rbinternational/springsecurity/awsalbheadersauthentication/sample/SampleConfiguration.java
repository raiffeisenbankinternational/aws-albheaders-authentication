package com.rbinternational.springsecurity.awsalbheadersauthentication.sample;

import com.rbinternational.springsecurity.awsalbheadersauthentication.*;
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
public class SampleConfiguration extends AWSAlbHeadersAuthenticationAbstractConfiguration {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // if EnableWebSecurity is used this could be used:
        // http.addFilterAfter(awsAlbAuthenticationFilter(), AnonymousAuthenticationFilter.class).authorizeRequests().anyRequest().hasRole("AUTH_USER");
        http.addFilterAfter(awsAlbAuthenticationFilter(), AnonymousAuthenticationFilter.class)
                .authorizeRequests().anyRequest().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(awsAlbHeadersAuthenticationProvider());
    }

    @Bean
    protected AWSAlbHeadersAuthenticationUserDetailsManager awsAlbHeadersAuthenticationUserDetailsManager() {
        AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl userDetailsManager
                = new AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl();
        userDetailsManager.setUserDetails(AWSAlbHeadersAuthenticationUserDetailsManagerSampleImpl.userDetailsOK);
        return userDetailsManager;
    }

    @Bean
    protected AWSAlbHeadersAuthenticationTokenValidator authTokenValidator() {
        return token -> {};
    }
}
