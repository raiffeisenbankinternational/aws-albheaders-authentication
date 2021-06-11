[![CodeQL](https://github.com/raiffeisenbankinternational/aws-albheaders-authentication/actions/workflows/codeql-analysis.yaml/badge.svg)](https://github.com/raiffeisenbankinternational/aws-albheaders-authentication/actions/workflows/codeql-analysis.yaml) [![Java CI](https://github.com/raiffeisenbankinternational/aws-albheaders-authentication/actions/workflows/javaci.yaml/badge.svg)](https://github.com/raiffeisenbankinternational/aws-albheaders-authentication/actions/workflows/javaci.yaml)

# AWS ALB Headers Authentication

This is a spring security authentication filter, implementing authentication for applications deployed behind an AWS ALB with authentication rule.
Basically, this is a kind of PreAuthenticatedFilter, because the user was already authenticated through the ALB's authentication rule. 
In this case the ALB sets three headers in the request:

- ```x-amzn-oidc-identity```: contains the sub attribute
- ```x-amzn-oidc-accesstoken```: contains the access token as JWT
- ```x-amzn-oidc-data```: contains the so called user claims as JWT (ALB specific)

For more details check the AWS documentation [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html).

## Implementation Details

The main authentication logic is implemented in [AWSAlbHeadersAuthenticationFilter](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationFilter.java).
It uses internally [AWSAlbHeadersAuthenticationConverter](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationConverter.java) to parse the request headers and extract them in an 
[AWSAlbHeadersAuthenticationToken](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationToken.java), which is a standard Spring security [AbstractAuthenticationToken](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/authentication/AbstractAuthenticationToken.html) implementation.
The converter can be replaced with subclass of Springs [AuthenticationConverter](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/web/authentication/AuthenticationConverter.html), if necessary. Optionally, a validation of the extracted headers can be
performed by implementing the [AWSAlbHeadersAuthenticationTokenValidater](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationTokenValidater.java ) interface. For example a JWT token validation can be 
implemented here (highly recommended!).

The provided [AWSAlbHeadersAuthenticationProvider](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationProvider.java) implements the logic to create or update an existing user in the application's backend. 
It delegates the concrete implementation of this task to custom implementations of the [AWSAlbHeadersAuthenticationUserDetailsManager](src/main/java/com/rbinternational/springsecurity/awsalbheadersauthentication/AWSAlbHeadersAuthenticationUserDetailsManager.java).
In database driven application this could be a Spring Service with some DAO behind it. The most important part of the implementation is to set correctly the 
user roles into the returned UserDetails, because these are used then for authorization purposes by the Spring authorization mechanisms.

## Sample Config
A running example protecting a REST controller is provided in the ```sample``` package. Short exerpt from the 
configuration:
```Java
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
```

Pleae also check the integration tests for some valid and invalid examples.
