package io.jenkins.plugins.tuleap_oauth;

import com.google.gson.Gson;
import hudson.model.User;
import hudson.security.UserMayOrMayNotExistException2;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class TuleapSecurityRealmTest {

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

    @BeforeEach
    void setUp() {
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
    void testAddDashAtTheEndOfTheTuleapUriWhenItIsMissing() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        TuleapConfiguration configuration = mock(TuleapConfiguration.class);
        when(this.pluginHelper.getConfiguration()).thenReturn(configuration);
        when(configuration.getDomainUrl()).thenReturn("https://jenkins.example.com");

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    void testItDoesNotAddADashAtTheOfTheUriIfTheUriAlreadyEndWithIt() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);

        TuleapConfiguration configuration = mock(TuleapConfiguration.class);
        when(this.pluginHelper.getConfiguration()).thenReturn(configuration);
        when(configuration.getDomainUrl()).thenReturn("https://jenkins.example.com");

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getTuleapUri());
    }

    @Test
    void testItShouldRedirectToClassicLogoutUrlWhenAnonymousUsersCanRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(true);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/", tuleapSecurityRealm.getPostLogOutUrl2(request, authentication));
    }

    @Test
    void testItShouldRedirectToTuleapLogoutUrlWhenAnonymousUsersCannotRead() {
        StaplerRequest request = mock(StaplerRequest.class);
        when(request.getContextPath()).thenReturn("https://jenkins.example.com");

        Authentication authentication = mock(Authentication.class);

        when(this.jenkins.hasPermission(Jenkins.READ)).thenReturn(false);

        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);

        assertEquals("https://jenkins.example.com/tuleapLogout", tuleapSecurityRealm.getPostLogOutUrl2(request, authentication));
    }

    @Test
    void testTheValidationIsOkWhenTheClientIdIsValid() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-1"));
        assertEquals(FormValidation.ok(), descriptor.doCheckClientId("tlp-client-id-48488484"));
    }

    @Test
    void testTheValidationIsNotOkWhenTheClientIdFormatIsNotValid() {
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
    void testTheValidationIsNotOkWhenTheClientIdIsEmpty() {
        TuleapSecurityRealm.DescriptorImpl descriptor = new TuleapSecurityRealm.DescriptorImpl();
        assertEquals(FormValidation.error(
            Messages.TuleapSecurityRealmDescriptor_CheckClientIdEmpty()).getMessage(),
            descriptor.doCheckClientId("").getMessage()
        );
    }

    @Test
    void testItShouldReturnATuleapUserDetailIfUserIsFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);

        final TuleapAuthenticationToken token = mock(TuleapAuthenticationToken.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(true);

        assertEquals(username, tuleapSecurityRealm.loadUserByUsername2(username).getUsername());
    }

    @Test
    void testItShouldNotReturnATuleapUserDetailIfUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final TuleapAuthenticationToken token = mock(TuleapAuthenticationToken.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);
        assertThrows(UsernameNotFoundException.class, () ->
            tuleapSecurityRealm.loadUserByUsername2(username));
    }

    @Test
    void testItShouldNotReturnATuleapUserDetailIfCurrentUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final Authentication token = mock(Authentication.class);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);
        assertThrows(UserMayOrMayNotExistException2.class, () ->
            tuleapSecurityRealm.loadUserByUsername2(username));
    }

    @Test
    void testItShouldNotReturnATuleapUserDetailIfCurrentUserHasNoToken() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final String username = "aTuleapUser";
        final User user = mock(User.class);
        when(this.pluginHelper.getUser(username)).thenReturn(user);
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(null);
        when(this.tuleapUserPropertyStorage.has(user)).thenReturn(false);
        assertThrows(UserMayOrMayNotExistException2.class, () ->
            tuleapSecurityRealm.loadUserByUsername2(username));
    }

    @Test
    void testItShouldReturnATuleapGroupDetailIfGroupIsFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);

        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token  = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";

        userDetails.addTuleapAuthority(new SimpleGrantedAuthority(groupName));

        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        when(this.tuleapGroupHelper.groupExistsOnTuleapServer(eq(groupName), eq(token), any())).thenReturn(true);

        assertEquals(groupName, tuleapSecurityRealm.loadGroupByGroupname2(groupName, false).getName());
    }

    @Test
    void testItShouldNotReturnATuleapGroupDetailIfGroupIsNotFoundableOnTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        when(this.tuleapGroupHelper.groupExistsOnTuleapServer(eq(groupName), eq(token), any())).thenReturn(false);
        assertThrows(UsernameNotFoundException.class, () ->
            tuleapSecurityRealm.loadGroupByGroupname2(groupName, false));
    }

    @Test
    void testItShouldNotReturnATuleapGroupDetailIfCurrentUserIsNotFromTuleap() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final Authentication token = mock(Authentication.class);
        final String groupName = "use-me#project_members";
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        assertThrows(UserMayOrMayNotExistException2.class, () ->
            tuleapSecurityRealm.loadGroupByGroupname2(groupName, false));
    }

    @Test
    void testItShouldNotReturnATuleapGroupDetailIfCurrentUserHasNoToken() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm( "", "");
        this.injectMock(tuleapSecurityRealm);
        final String groupName = "use-me#project_members";
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(null);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(true);
        assertThrows(UserMayOrMayNotExistException2.class, () ->
            tuleapSecurityRealm.loadGroupByGroupname2(groupName, false));
    }

    @Test
    void testItShouldNotReturnATuleapGroupDetailIfGroupNameIsNotOfTuleapFormat() {
        TuleapSecurityRealm tuleapSecurityRealm = new TuleapSecurityRealm("", "");
        this.injectMock(tuleapSecurityRealm);
        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapUserDetails userDetails = new TuleapUserDetails("someUser");
        final TuleapAuthenticationToken token = new TuleapAuthenticationToken(userDetails, accessToken);
        final String groupName = "use-me#project_members";
        when(this.pluginHelper.getCurrentUserAuthenticationToken()).thenReturn(token);
        when(this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)).thenReturn(false);
        assertThrows(UsernameNotFoundException.class, () ->
            tuleapSecurityRealm.loadGroupByGroupname2(groupName, false));
    }
}
