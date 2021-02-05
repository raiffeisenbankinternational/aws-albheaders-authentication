package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Implements the handling logic for the {@link org.springframework.security.core.Authentication}. Normally stores the
 * request user into the database or other backend or refreshes its attributes, if found. The roles as returned by the
 * backend will be used to construct the user's {@link org.springframework.security.core.GrantedAuthority} list.
 */
public interface AWSAlbHeadersAuthenticationUserDetailsManager extends AuthenticationUserDetailsService<AWSAlbHeadersAuthenticationToken> {

    /**
     * Creates a new user in the applications' backend.
     *
     * @param userDetails the user from the request
     *
     * @return the userDetails from the backend, most important the application defined roles, assigned to the user
     *
     * @throws AWSAlbHeadersAuthenticationUserDetailsManagerException in case of error from the backend
     */
    UserDetails createUser(AWSAlbHeadersAuthenticationToken userDetails) throws AWSAlbHeadersAuthenticationUserDetailsManagerException;

    /**
     * Updates already existing user in the applocations' backend.
     *
     * @param userDetails the user from the request
     *
     * @return the userDetails from the backend, most important the application defined roles, assigned to the user
     *
     * @throws AWSAlbHeadersAuthenticationUserDetailsManagerException in case of error from the backend
     */
    UserDetails updateUser(AWSAlbHeadersAuthenticationToken userDetails) throws AWSAlbHeadersAuthenticationUserDetailsManagerException;

    /**
     * Removed the exception from the declaration. If the user doesn't yet exist the method must return <code>null</code>!
     *
     * @param token
     *
     * @return <code>null</code>, if the user doesn't exist yet to signal that it must be created
     *
     * @throws AWSAlbHeadersAuthenticationUserDetailsManagerException in case of error from the backend
     */
    @Override
    UserDetails loadUserDetails(AWSAlbHeadersAuthenticationToken token) throws AWSAlbHeadersAuthenticationUserDetailsManagerException;
}
