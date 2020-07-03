package io.jenkins.plugins.tuleap_oauth;

import org.acegisecurity.providers.AbstractAuthenticationToken;

public class TuleapAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final TuleapUserDetails tuleapUserDetails;

    public TuleapAuthenticationToken(TuleapUserDetails tuleapUserDetails) {
        super(tuleapUserDetails.getAuthorities());

        this.tuleapUserDetails = tuleapUserDetails;
        this.setAuthenticated(true);
    }

    @Override
    public String getCredentials() {
        return "";
    }

    @Override
    public String getPrincipal() {
        return this.tuleapUserDetails.getUsername();
    }

    public TuleapUserDetails getTuleapUserDetails() {
        return this.tuleapUserDetails;
    }
}
