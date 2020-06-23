package io.jenkins.plugins.tuleap_oauth;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.acegisecurity.providers.AbstractAuthenticationToken;

public class TuleapAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final transient AccessToken accessToken;
    private final TuleapUserDetails tuleapUserDetails;

    public TuleapAuthenticationToken(
        TuleapUserDetails tuleapUserDetails,
        AccessToken accessToken
    ){
        super(tuleapUserDetails.getAuthorities());

        this.tuleapUserDetails = tuleapUserDetails;
        this.accessToken = accessToken;
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

    public AccessToken getAccessToken() {
        return this.accessToken;
    }
}
