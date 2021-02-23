package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The filter to be registered in the {@link org.springframework.security.config.annotation.web.builders.HttpSecurity},
 * to process the requests from the ALB.
 * <ul>
 *     <li>
 *         First the {@link AWSAlbHeadersAuthenticationConverter} is used to extract the headers from the request. If this
 *         fails an {@link AuthenticationException} is immediately thrown.
 *     </li>
 *     <li>
 *         If the extraction is successful and there is a {@link AWSAlbHeadersAuthenticationTokenValidator} set then a
 *         validation is performed, using {@link AWSAlbHeadersAuthenticationTokenValidator#validate(AWSAlbHeadersAuthenticationToken)}
 *         method. The validater can report invalid tokens by throwing an {@link AuthenticationException}.</li>
 *     <li>
 *         If eveyrthing goes well then the {@link AWSAlbHeadersAuthenticationProvider#authenticate(Authentication)} is
 *         called to process the {@link org.springframework.security.core.userdetails.UserDetails}
 *     </li>
 *     <li>
 *         At the end the {@link Authentication} is saved in the {@link org.springframework.security.core.context.SecurityContext}
 *         and the execution is passed to the next filter in the {@link FilterChain}
 *     </li>
 * </ul>
 *
 * In contrast to the standard Spring security contract this filter doesn't allow unauthenticated requests to be passed for
 * further processing (returning <code>null</code> from the authentication logic)!
 */
public class AWSAlbHeadersAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final Logger logger = LoggerFactory.getLogger(AWSAlbHeadersAuthenticationFilter.class);

    private AWSAlbHeadersAuthenticationTokenValidator authenticationTokenValidater = null;


    private AuthenticationConverter authenticationConverter = new AWSAlbHeadersAuthenticationConverter();


    public AWSAlbHeadersAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    /**
     * Sets the validater for the request headers - possibly Jwt token validation
     *
     * @param authenticationTokenValidater
     */
    public void setAuthenticationTokenValidater(AWSAlbHeadersAuthenticationTokenValidator authenticationTokenValidater) {
        this.authenticationTokenValidater = authenticationTokenValidater;
    }

    /**
     * customizes the used {@link AuthenticationConverter}, if necessary
     *
     * @param authenticationConverter
     */
    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, ServletException {
        Authentication authenticationRequest = this.authenticationConverter.convert(request);
        this.logger.debug("authenticationRequest = {}, trying to authenticate", authenticationRequest);
        if (this.authenticationTokenValidater != null) {
            this.logger.debug("authenticationRequest = {}, trying to validate", authenticationRequest);
            this.authenticationTokenValidater.validate((AWSAlbHeadersAuthenticationToken) authenticationRequest);
        }
        Authentication authenticationResult;
        try {
            authenticationResult = this.getAuthenticationManager().authenticate(authenticationRequest);
        }
        catch (AWSAlbHeadersAuthenticationUserDetailsManagerException e) {
            throw new ServletException(e);
        }
        this.logger.debug("authenticationRequest = {}, authenticated", authenticationResult);
        return authenticationResult;
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return true;
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
                throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(request, response);
    }
}
