package io.jenkins.plugins.tuleap_oauth.helper;

import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TuleapAuthorizationCodeUrlBuilderImplTest {

    private PluginHelper pluginHelper;
    private PKCECodeBuilder codeBuilder;

    private Jenkins jenkins;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
        this.codeBuilder = mock(PKCECodeBuilder.class);

        this.jenkins = mock(Jenkins.class);
        when(this.pluginHelper.getJenkinsInstance()).thenReturn(this.jenkins);
    }

    @Test
    public void testItReturnsTheAuthenticationErrorActionUrlWhenUrlIsNotHttps() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        StaplerRequest request = mock(StaplerRequest.class);

        when(this.pluginHelper.isHttpsUrl("http://fail.example.com")).thenReturn(false);

        when(jenkins.getRootUrl()).thenReturn("https://jenkins.example.com/");

        TuleapAuthorizationCodeUrlBuilderImpl tuleapAuthorizationCodeUrlBuilder = new TuleapAuthorizationCodeUrlBuilderImpl(this.pluginHelper, this.codeBuilder);
        String redirectUri = tuleapAuthorizationCodeUrlBuilder.
            buildRedirectUrlAndStoreSessionAttribute(
                request,
                "http://fail.example.com",
                ""
            );

        verify(this.pluginHelper, never()).buildRandomBase64EncodedURLSafeString();
        assertEquals("https://jenkins.example.com/tuleapError", redirectUri);
    }

    @Test
    public void testItShouldReturnTheAuthorizationCodeUriWithTheRightParameters() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        StaplerRequest request = mock(StaplerRequest.class);

        String tuleapUri = "https://tuleap.example.com/";
        when(this.pluginHelper.isHttpsUrl(tuleapUri)).thenReturn(true);

        String stateAndNonce = "Brabus";
        when(this.pluginHelper.buildRandomBase64EncodedURLSafeString()).thenReturn(stateAndNonce);

        HttpSession session = spy(HttpSession.class);
        when(request.getSession()).thenReturn(session);

        String rootUrl = "https://jenkins.example.com/";
        when(this.jenkins.getRootUrl()).thenReturn(rootUrl);

        String codeVerifier = "A35AMG";
        when(this.codeBuilder.buildCodeVerifier()).thenReturn(codeVerifier);
        when(this.codeBuilder.buildCodeChallenge(codeVerifier)).thenReturn("B35S");

        String clientId = "123";

        String expectedUri = "https://tuleap.example.com/oauth2/authorize?" +
            "response_type=code" +
            "&client_id=123" +
            "&redirect_uri=" + URLEncoder.encode("https://jenkins.example.com/securityRealm/finishLogin", UTF_8.name()) +
            "&scope="+ URLEncoder.encode("read:project read:user_membership openid profile offline_access", UTF_8.name()) +
            "&state=Brabus" +
            "&code_challenge=B35S" +
            "&code_challenge_method=S256" +
            "&nonce=Brabus";


        TuleapAuthorizationCodeUrlBuilderImpl tuleapAuthorizationCodeUrlBuilder = new TuleapAuthorizationCodeUrlBuilderImpl(this.pluginHelper, this.codeBuilder);

        String redirectUri = tuleapAuthorizationCodeUrlBuilder.buildRedirectUrlAndStoreSessionAttribute(request, tuleapUri, clientId);

        verify(session, times(1)).setAttribute(TuleapSecurityRealm.STATE_SESSION_ATTRIBUTE, stateAndNonce);
        verify(session, times(1)).setAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE, stateAndNonce);
        verify(session, times(1)).setAttribute(TuleapSecurityRealm.STATE_SESSION_ATTRIBUTE, stateAndNonce);
        verify(session, times(1)).setAttribute(TuleapSecurityRealm.JENKINS_REDIRECT_URI_ATTRIBUTE, "https://jenkins.example.com/securityRealm/finishLogin");

        assertEquals(expectedUri, redirectUri);
    }
}
