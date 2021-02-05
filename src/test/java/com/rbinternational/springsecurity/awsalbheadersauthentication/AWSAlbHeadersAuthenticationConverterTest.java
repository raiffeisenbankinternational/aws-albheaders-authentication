package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

public class AWSAlbHeadersAuthenticationConverterTest {

    private static final String SUB_VALUE = "41cf8257-cf00-4d62-a321-9bdf810be470";
    private static final String ACCESS_TOKEN_VALUE = "eyj.access.token";
    private static final String USER_CLAIMS_VALUE = "eyJ.user.claims==";

    @Test
    public void testAnyMissingHeaderThrowsAuthenticationException() {
        HttpServletRequest request = new MockHttpServletRequest();
        assertThrows(AWSAlbHeadersAuthenticationException.class,
                () -> new AWSAlbHeadersAuthenticationConverter().convert(request));
    }

    @Test
    public void testMissingSubHeaderThrowsAuthenticationException() {
        MockHttpServletRequest request = getAuthenticatedRequest();
        request.removeHeader(AWSAlbHeadersAuthenticationConverter.SUB_HEADER);
        Exception exception = assertThrows(AWSAlbHeadersAuthenticationException.class,
                () -> new AWSAlbHeadersAuthenticationConverter().convert(request));
        System.out.println("AWSAlbHeadersAuthenticationConverterTest.testMissingSubHeaderThrowsAuthenticationException: " + exception.getMessage());
        assertTrue(exception.getMessage().contains(AWSAlbHeadersAuthenticationConverter.SUB_HEADER));
    }

    @Test
    public void testMissingAccessTokenHeaderThrowsAuthenticationException() {
        MockHttpServletRequest request = getAuthenticatedRequest();
        request.removeHeader(AWSAlbHeadersAuthenticationConverter.ACCESS_TOKEN_HEADER);
        Exception exception = assertThrows(AWSAlbHeadersAuthenticationException.class,
                () -> new AWSAlbHeadersAuthenticationConverter().convert(request));
        assertTrue(exception.getMessage().contains(AWSAlbHeadersAuthenticationConverter.ACCESS_TOKEN_HEADER));
    }

    @Test
    public void testMissingUserClaimsHeaderThrowsAuthenticationException() {
        MockHttpServletRequest request = getAuthenticatedRequest();
        request.removeHeader(AWSAlbHeadersAuthenticationConverter.USER_CLAIMS_HEADER);
        Exception exception = assertThrows(AWSAlbHeadersAuthenticationException.class,
                () -> new AWSAlbHeadersAuthenticationConverter().convert(request));
        assertTrue(exception.getMessage().contains(AWSAlbHeadersAuthenticationConverter.USER_CLAIMS_HEADER));
    }

    @Test
    public void testAuthenticatedRequestHasAuthenticaton() {
        HttpServletRequest request = getAuthenticatedRequest();
        Authentication authentication = new AWSAlbHeadersAuthenticationConverter().convert(request);
        assertNotNull(authentication);
    }

    @Test
    public void testAuthenticatedRequestHasValidPrincipal() {
        HttpServletRequest request = getAuthenticatedRequest();
        Authentication authentication = new AWSAlbHeadersAuthenticationConverter().convert(request);
        assertEquals(SUB_VALUE, authentication.getPrincipal());
    }

    @Test
    public void testAuthenticatedRequestHasValidAccessTokenValue() {
        HttpServletRequest request = getAuthenticatedRequest();
        Authentication authentication = new AWSAlbHeadersAuthenticationConverter().convert(request);
        assertEquals(ACCESS_TOKEN_VALUE, ((AWSAlbHeadersAuthenticationToken) authentication).getAccessToken());
    }

    @Test
    public void testAuthenticatedRequestHasValidUserClaimsTokenValue() {
        HttpServletRequest request = getAuthenticatedRequest();
        Authentication authentication = new AWSAlbHeadersAuthenticationConverter().convert(request);
        assertEquals(USER_CLAIMS_VALUE, ((AWSAlbHeadersAuthenticationToken) authentication).getUserClaimsToken());
    }

    private MockHttpServletRequest getAuthenticatedRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(AWSAlbHeadersAuthenticationConverter.SUB_HEADER, SUB_VALUE);
        request.addHeader(AWSAlbHeadersAuthenticationConverter.ACCESS_TOKEN_HEADER, ACCESS_TOKEN_VALUE);
        request.addHeader(AWSAlbHeadersAuthenticationConverter.USER_CLAIMS_HEADER, USER_CLAIMS_VALUE);
        return request;
    }
}
