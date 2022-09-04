package com.prgrms.devcourse.user;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

public class LoginRequest {

    private String principal;

    private String credentials;

    protected LoginRequest() {}

    public LoginRequest(String principal, String credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getCredentials() {
        return credentials;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("principal", principal)
                .append("credentials", credentials)
                .toString();
    }

}