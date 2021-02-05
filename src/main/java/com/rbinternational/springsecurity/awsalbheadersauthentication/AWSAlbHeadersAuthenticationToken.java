package com.rbinternational.springsecurity.awsalbheadersauthentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Extends the {@link AbstractAuthenticationToken} with additional properties to store the extracted headers information
 * - sub, access token and user claims token.
 */
public class AWSAlbHeadersAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private final Object credentials;

    private String accessToken;

    private String userClaimsToken;

    private String sub;

    public AWSAlbHeadersAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getUserClaimsToken() {
        return userClaimsToken;
    }

    public void setUserClaimsToken(String userClaimsToken) {
        this.userClaimsToken = userClaimsToken;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    @Override
    public boolean equals(Object obj) {
        boolean superEquals = super.equals(obj);
        if (!superEquals || !(obj instanceof AWSAlbHeadersAuthenticationToken)) {
            return false;
        }
        AWSAlbHeadersAuthenticationToken other = (AWSAlbHeadersAuthenticationToken) obj;
        if (this.getSub() == null && other.getSub() != null) {
            return false;
        }
        if (this.getSub() != null && !this.getSub().equals(other.getSub())) {
            return false;
        }
        if (this.getAccessToken() == null && other.getAccessToken() != null) {
            return false;
        }
        if (this.getAccessToken() != null && !this.getAccessToken().equals(other.getAccessToken())) {
            return false;
        }
        if (this.getUserClaimsToken() == null && other.getUserClaimsToken() != null) {
            return false;
        }
        if (this.getUserClaimsToken() != null && !this.getUserClaimsToken().equals(other.getUserClaimsToken())) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int code = super.hashCode();
        if (this.getSub() != null) {
            code ^= this.getSub().hashCode();
        }
        if (this.getAccessToken() != null) {
            code ^= this.getAccessToken().hashCode();
        }
        if (this.getUserClaimsToken() != null) {
            code ^= this.getUserClaimsToken().hashCode();
        }
        return code;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("Sub=").append(getSub()).append(", ");
        sb.append("AccessToken=").append(getAccessToken()).append(", ");
        sb.append("UserClaimsToken=").append(getUserClaimsToken()).append("] ");
        return sb.toString();
    }
}
