package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.http.HttpSession;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

class AuthorizationCodeCheckerImplTest {

    private PluginHelper helper;

    @BeforeEach
    void setUp() {
        this.helper = mock(PluginHelper.class);
    }

    @Test
    void testItReturnsFalseWhereTheRedirectUriIsNotSaved() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnsFalseWhereTheRedirectUriAndTheExpectedUriDoesNotMatch() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https:/yeeeeeet.example.com/fail");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnFalseWhenThereIsNoCodeReturned() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("");
        verify(request, never()).getParameter("state");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnFalseWhenThereIsNoStateReturned() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnFalseWhenThereIsNoStateStoredInSession() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnFalseWhenTheStoredSessionStateAndTheReturnedStateAreDifferent() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("naha");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnFalseWhenThereIsNoCodeVerifierStoredInSession() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("issou");
        when(session.getAttribute("code_verifier")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    void testItReturnTrueAuthorizationChecksAreOk() {
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn("https://redirect.example.com/securityRealm/finishLogin");

        Jenkins jenkins = mock(Jenkins.class);
        when(this.helper.getJenkinsInstance()).thenReturn(jenkins);
        when(jenkins.getRootUrl()).thenReturn("https://redirect.example.com/");

        when(request.getParameter("code")).thenReturn("1234");
        when(request.getParameter("state")).thenReturn("issou");
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("state")).thenReturn("issou");
        when(session.getAttribute("code_verifier")).thenReturn("tchiki tchiki");

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertTrue(authorizationCodeChecker.checkAuthorizationCode(request));
    }
}
