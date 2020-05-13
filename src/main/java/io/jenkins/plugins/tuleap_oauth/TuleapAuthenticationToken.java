package io.jenkins.plugins.tuleap_oauth;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

public class TuleapAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private transient final UserInfo userInfo;

    public TuleapAuthenticationToken(UserInfo userInfo){
        super(new GrantedAuthority[] {SecurityRealm.AUTHENTICATED_AUTHORITY});

        this.userInfo = userInfo;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.userInfo.getUsername();
    }
}
