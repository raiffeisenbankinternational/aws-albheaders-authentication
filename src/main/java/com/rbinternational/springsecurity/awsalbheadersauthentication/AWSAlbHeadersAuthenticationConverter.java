package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * Converts the headers coming from the ALB to the corresponding {@link AWSAlbHeadersAuthenticationToken} authentication
 * object.
 * see also <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html">Authenticate users using an Application Load Balancer</a>
 */
public class AWSAlbHeadersAuthenticationConverter implements AuthenticationConverter {

    private final Logger logger = LoggerFactory.getLogger(AWSAlbHeadersAuthenticationConverter.class);

    /**
     * Contains the access token from the token endpoint, in JSON web tokens (JWT) format.
     */
    public static final String ACCESS_TOKEN_HEADER = "x-amzn-oidc-accesstoken";

    /**
     * Contains the user claims, in JSON web tokens (JWT) format.
     */
    public static final String USER_CLAIMS_HEADER = "x-amzn-oidc-data";

    /**
     * Contains the subject field (sub) from the user info endpoint, in plain text.
     */
    public static final String SUB_HEADER = "x-amzn-oidc-identity";

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    @Override
    public Authentication convert(HttpServletRequest request) throws AuthenticationException {
        String accessToken = null;
        String userClaims = null;
        String sub = null;
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            this.logger.debug("processing header name: {}", name);
            if (name.equalsIgnoreCase(ACCESS_TOKEN_HEADER)) {
                accessToken = request.getHeader(name);
                this.logger.debug("got accessToken: {}", accessToken);
            }
            else if (name.equalsIgnoreCase(USER_CLAIMS_HEADER)) {
                userClaims = request.getHeader(name);
                this.logger.debug("found userClaims: {}", userClaims);
            }
            else if (name.equalsIgnoreCase(SUB_HEADER)) {
                sub = request.getHeader(name);
                this.logger.debug("foung sub: {}", sub);
            }
            if (accessToken != null && userClaims != null && sub != null) {
                break;
            }
        }
        if (!StringUtils.hasText(sub)) {
            this.logger.error("{} request header is missing or empty: {}", SUB_HEADER, sub);
            throw new AWSAlbHeadersAuthenticationException(String.format("%s header is missing", SUB_HEADER));
        }
        if (!StringUtils.hasText(accessToken)) {
            this.logger.error("{} request header is missing or empty: {}", ACCESS_TOKEN_HEADER, accessToken);
            throw new AWSAlbHeadersAuthenticationException(String.format("%s header is missing", ACCESS_TOKEN_HEADER));
        }
        if (!StringUtils.hasText(userClaims)) {
            this.logger.error("{} request header is missing or empty: {}", USER_CLAIMS_HEADER, userClaims);
            throw new AWSAlbHeadersAuthenticationException(String.format("%s header is missing", USER_CLAIMS_HEADER));
        }
        AWSAlbHeadersAuthenticationToken authResult = new AWSAlbHeadersAuthenticationToken(sub, null, null);
        authResult.setAccessToken(accessToken);
        authResult.setSub(sub);
        authResult.setUserClaimsToken(userClaims);
        authResult.setDetails(authenticationDetailsSource.buildDetails(request));
        this.logger.debug("Created authResult for authentication: {}", authResult);
        return authResult;
    }
}
