package io.jenkins.plugins.tuleap_oauth;

import com.google.gson.Gson;
import hudson.model.User;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FormValidation;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessTokenApi;
import io.jenkins.plugins.tuleap_api.client.authentication.OpenIDClientApi;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.IDTokenChecker;
import io.jenkins.plugins.tuleap_oauth.helper.*;
import io.jenkins.plugins.tuleap_server_configuration.TuleapConfiguration;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TuleapSecurityRealmTest {

    private PluginHelper pluginHelper;
    private AuthorizationCodeChecker authorizationCodeChecker;
    private AccessTokenChecker accessTokenChecker;
    private Gson gson;
    private IDTokenChecker IDTokenChecker;
    private TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder;
    private AccessTokenApi accessTokenApi;
    private OpenIDClientApi openIDClientApi;
    private TuleapUserPropertyStorage tuleapUserPropertyStorage;
    private UserAuthoritiesRetriever userAuthoritiesRetriever;
    private TuleapGroupHelper tuleapGroupHelper;

    private Jenkins jenkins;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelperImpl.class);
        this.authorizationCodeChecker = mock(AuthorizationCodeChecker.class);
        this.accessTokenChecker = mock(AccessTokenChecker.class);
        this.IDTokenChecker = mock(IDTokenChecker.class);
        this.authorizationCodeUrlBuilder = mock(TuleapAuthorizationCodeUrlBuilder.class);
        this.accessTokenApi = mock(AccessTokenApi.class);
        this.openIDClientApi = mock(OpenIDClientApi.class);
        this.tuleapUserPropertyStorage = mock(TuleapUserPropertyStorage.class);
        this.userAuthoritiesRetriever = mock(UserAuthoritiesRetriever.class);
        this.tuleapGroupHelper = mock(TuleapGroupHelper.class);
        this.gson = mock(Gson.class);

        this.jenkins = mock(Jenkins.class);
        when(pluginHelper.getJenkinsInstance()).thenReturn(jenkins);
    }

    private void injectMock(TuleapSecurityRealm securityRealm) {
        securityRealm.setPluginHelper(this.pluginHelper);
        securityRealm.setAuthorizationCodeChecker(this.authorizationCodeChecker);
        securityRealm.setAccessTokenChecker(this.accessTokenChecker);
        securityRealm.setGson(this.gson);
        securityRealm.setIDTokenChecker(this.IDTokenChecker);
        securityRealm.setAuthorizationCodeUrlBuilder(this.authorizationCodeUrlBuilder);
        securityRealm.setAccessTokenApi(this.accessTokenApi);
        securityRealm.setOpenIDClientApi(this.openIDClientApi);
        securityRealm.setTuleapUserPropertyStorage(this.tuleapUserPropertyStorage);
        securityRealm.setUserAuthoritiesRetriever(this.userAuthoritiesRetriever);
        securityRealm.setTuleapGroupHelper(this.tuleapGroupHelper);
    }

    @Test
    public void testAddDashAtTheEndOfTheTuleapUriWhenItIsMissing() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        TuleapConfiguration configuration = mock(TuleapConfiguration.class);
        when(this.pluginHelper.getConfiguration()).thenReturn(configuration);
        when(configuration.getDomainUrl()).thenReturn("https://jenkins.example.com");

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItDoesNotAddADashAtTheOfTheUriIfTheUriAlreadyEndWithIt() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        TuleapConfiguration configuration = mock(TuleapConfiguration.class);
        when(this.pluginHelper.getConfiguration()).thenReturn(configuration);
        when(configuration.getDomainUrl()).thenReturn("https://jenkins.example.com");

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    public void testItShouldRedirectToClassicLogoutUrlWhenAnonymousUsersCanRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);
        when(authentication.toSpring()).thenReturn(this.getSpringAuthentication());

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(true);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

    @Test
    public void testItShouldRedirectToTuleapLogoutUrlWhenAnonymousUsersCannotRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(false);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/tuleapLogout", tuleapSecurityRealm.getPostLogOutUrl(request, authentication));
    }

    @Test
    public void testTheValidationIsOkWhenTheClientIdIsValid() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-1"));
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-48488484"));
    }

    @Test
    public void testTheValidationIsNotOkWhenTheClientIdFormatIsNotValid() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(
            FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-client-id-fghhf").getMessage()
        );
        assertEquals(FormValidation.error(
                Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("freogjeuobnfb").getMessage()
        );
        assertEquals(FormValidation.error(
                Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("snv-tlp-client-id-10").getMessage()
        );
        assertEquals(FormValidation.error(
                Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-id-10").getMessage()
        );

        assertEquals(FormValidation.error(
                Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat()).getMessage(),
            descriptor.doCheckClientId("tlp-client-id-").getMessage()
        );
    }

    @Test
    public void testTheValidationIsNotOkWhenTheClientIdIsEmpty() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.error(
                Messages.TuleapSecurityRealmDescriptor_CheckClientIdEmpty()).getMessage(),
            descriptor.doCheckClientId("").getMessage()
        );
    }

    @Test
    public void testItShouldReturnATuleapUserDetailIfUserIsFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final TuleapAuthenticationToken token = mock(TuleapAuthenticationToken.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(true);

        assertEquals(tuleapSecurityRealm.loadUserByUsername(username).getUsername(), username);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testItShouldNotReturnATuleapUserDetailIfUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final TuleapAuthenticationToken token = mock(TuleapAuthenticationToken.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);

        tuleapSecurityRealm.loadUserByUsername(username);
    }

    @Test(expected = UserMayOrMayNotExistException.class)
    public void testItShouldNotReturnATuleapUserDetailIfCurrentUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final Authentication token = mock(Authentication.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);

        tuleapSecurityRealm.loadUserByUsername(username);
    }

    @Test(expected = UserMayOrMayNotExistException.class)
    public void testItShouldNotReturnATuleapUserDetailIfCurrentUserHasNoToken() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(null);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);

        tuleapSecurityRealm.loadUserByUsername(username);
    }

    @Test
    public void testItShouldReturnATuleapGroupDetailIfGroupIsFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";

        userDetails.addTuleapAuthority(new GrantedAuthorityImpl(groupName));

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        when(this.tuleapGroupHelper.groupExistsOnTuleapServer(eq(groupName), eq(token), any())).thenReturn(true);

        assertEquals(tuleapSecurityRealm.loadGroupByGroupname(groupName).getName(), groupName);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testItShouldNotReturnATuleapGroupDetailIfGroupIsNotFoundableOnTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        when(this.tuleapGroupHelper.groupExistsOnTuleapServer(eq(groupName), eq(token), any())).thenReturn(false);

        tuleapSecurityRealm.loadGroupByGroupname(groupName);
    }

    @Test(expected = UserMayOrMayNotExistException.class)
    public void testItShouldNotReturnATuleapGroupDetailIfCurrentUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final Authentication token = mock(Authentication.class);
        final String groupName = "use-me#project_members";

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);

        tuleapSecurityRealm.loadGroupByGroupname(groupName);
    }

    @Test(expected = UserMayOrMayNotExistException.class)
    public void testItShouldNotReturnATuleapGroupDetailIfCurrentUserHasNoToken() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final String groupName = "use-me#project_members";

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(null);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);

        tuleapSecurityRealm.loadGroupByGroupname(groupName);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testItShouldNotReturnATuleapGroupDetailIfGroupNameIsNotOfTuleapFormat() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(false);

        tuleapSecurityRealm.loadGroupByGroupname(groupName);
    }

    private org.springframework.security.core.Authentication getSpringAuthentication() {
        return new org.springframework.security.core.Authentication() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return false;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

            }

            @Override
            public String getName() {
                return null;
            }
        };
    }

}
