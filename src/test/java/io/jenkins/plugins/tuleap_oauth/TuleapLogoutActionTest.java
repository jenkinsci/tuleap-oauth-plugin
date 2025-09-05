package io.jenkins.plugins.tuleap_oauth;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class TuleapLogoutActionTest {

    @Test
    void testItReturnsTheTuleapUriWhenTheTuleapAuthenticationIsEnabled() {
        PluginHelper helper = mock(PluginHelper.class);
        Jenkins jenkins = mock(Jenkins.class);

        when(helper.getJenkinsInstance()).thenReturn(jenkins);

        TuleapSecurityRealm tuleapSecurityRealm = mock(TuleapSecurityRealm.class);
        when(tuleapSecurityRealm.getTuleapUri()).thenReturn("https://tuleap.example.com/");
        when(jenkins.getSecurityRealm()).thenReturn(tuleapSecurityRealm);

        TuleapLogoutAction logoutAction = new TuleapLogoutAction(helper);
        assertEquals("https://tuleap.example.com/", logoutAction.getTuleapUrl());
    }

    @Test
    void testItReturnEmptyStringWhenTheTuleapAuthenticationIsEnabled() {
        PluginHelper helper = mock(PluginHelper.class);
        Jenkins jenkins = mock(Jenkins.class);

        when(helper.getJenkinsInstance()).thenReturn(jenkins);

        SecurityRealm securityRealm = mock(SecurityRealm.class);
        when(jenkins.getSecurityRealm()).thenReturn(securityRealm);

        TuleapLogoutAction logoutAction = new TuleapLogoutAction(helper);
        assertEquals("", logoutAction.getTuleapUrl());
    }
}
