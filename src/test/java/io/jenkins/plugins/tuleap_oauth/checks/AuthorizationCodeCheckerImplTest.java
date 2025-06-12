package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest2;

import jakarta.servlet.http.HttpSession;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AuthorizationCodeCheckerImplTest {

    private PluginHelper helper;

    @Before
    public void setUp() {
        this.helper = mock(PluginHelper.class);
    }

    @Test
    public void testItReturnsFalseWhereTheRedirectUriIsNotSaved() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
        HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute("redirect_uri")).thenReturn(null);

        AuthorizationCodeCheckerImpl authorizationCodeChecker = new AuthorizationCodeCheckerImpl(this.helper);
        assertFalse(authorizationCodeChecker.checkAuthorizationCode(request));
    }

    @Test
    public void testItReturnsFalseWhereTheRedirectUriAndTheExpectedUriDoesNotMatch() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnFalseWhenThereIsNoCodeReturned() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnFalseWhenThereIsNoStateReturned(){
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnFalseWhenThereIsNoStateStoredInSession(){
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnFalseWhenTheStoredSessionStateAndTheReturnedStateAreDifferent() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnFalseWhenThereIsNoCodeVerifierStoredInSession() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
    public void testItReturnTrueAuthorizationChecksAreOk() {
        StaplerRequest2 request = mock(StaplerRequest2.class);
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
