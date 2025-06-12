package io.jenkins.plugins.tuleap_oauth;

import com.auth0.jwk.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.inject.Guice;
import com.google.inject.Inject;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessTokenApi;
import io.jenkins.plugins.tuleap_api.client.authentication.OpenIDClientApi;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import io.jenkins.plugins.tuleap_oauth.checks.AccessTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.AuthorizationCodeChecker;
import io.jenkins.plugins.tuleap_oauth.checks.IDTokenChecker;
import io.jenkins.plugins.tuleap_oauth.checks.UserInfoChecker;
import io.jenkins.plugins.tuleap_oauth.guice.TuleapOAuth2GuiceModule;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapAuthorizationCodeUrlBuilder;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapGroupHelper;
import io.jenkins.plugins.tuleap_oauth.helper.UserAuthoritiesRetriever;
import io.jenkins.plugins.tuleap_server_configuration.TuleapConfiguration;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.verb.POST;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Collection;

public class TuleapSecurityRealm extends SecurityRealm {

    private String clientId;
    private Secret clientSecret;

    private static final String LOGIN_URL = "securityRealm/commenceLogin";
    public static final String REDIRECT_URI = "securityRealm/finishLogin";

    private static final String REDIRECT_TO_SESSION_ATTRIBUTE = TuleapSecurityRealm.class.getName() + "-redirect-to";
    public static final String CODE_VERIFIER_SESSION_ATTRIBUTE = "code_verifier";
    public static final String STATE_SESSION_ATTRIBUTE = "state";
    public static final String JENKINS_REDIRECT_URI_ATTRIBUTE = "redirect_uri";
    public static final String NONCE_ATTRIBUTE = "nonce";

    public static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";

    public static final String SCOPES = "read:project read:user_membership openid profile email";
    public static final String CODE_CHALLENGE_METHOD = "S256";

    private transient AuthorizationCodeChecker authorizationCodeChecker;
    private transient PluginHelper pluginHelper;
    private transient AccessTokenChecker accessTokenChecker;
    private transient Gson gson;
    private transient IDTokenChecker IDTokenChecker;
    private transient UserInfoChecker userInfoChecker;
    private transient TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder;
    private transient TuleapUserPropertyStorage tuleapUserPropertyStorage;
    private transient UserAuthoritiesRetriever userAuthoritiesRetriever;

    private transient AccessTokenApi accessTokenApi;
    private transient OpenIDClientApi openIDClientApi;
    private transient TuleapGroupHelper tuleapGroupHelper;

    @DataBoundConstructor
    public TuleapSecurityRealm(String clientId, String clientSecret) {
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.setClientSecret(Util.fixEmptyAndTrim(clientSecret));
    }

    @Inject
    public void setOpenIDClientApi(OpenIDClientApi openIDClientApi) {
        this.openIDClientApi = openIDClientApi;
    }

    @Inject
    public void setAccessTokenApi(AccessTokenApi accessTokenApi) {
        this.accessTokenApi = accessTokenApi;
    }

    @Inject
    public void setAuthorizationCodeUrlBuilder(TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder) {
        this.authorizationCodeUrlBuilder = authorizationCodeUrlBuilder;
    }

    @Inject
    public void setUserInfoChecker(UserInfoChecker userInfoChecker) {
        this.userInfoChecker = userInfoChecker;
    }

    @Inject
    public void setIDTokenChecker(IDTokenChecker IDTokenChecker) {
        this.IDTokenChecker = IDTokenChecker;
    }

    @Inject
    public void setGson(Gson gson) {
        this.gson = gson;
    }

    @Inject
    public void setAuthorizationCodeChecker(AuthorizationCodeChecker authorizationCodeChecker) {
        this.authorizationCodeChecker = authorizationCodeChecker;
    }

    @Inject
    public void setPluginHelper(PluginHelper pluginHelper) {
        this.pluginHelper = pluginHelper;
    }

    @Inject
    public void setAccessTokenChecker(AccessTokenChecker accessTokenChecker) {
        this.accessTokenChecker = accessTokenChecker;
    }

    @Inject
    public void setTuleapUserPropertyStorage(TuleapUserPropertyStorage tuleapUserPropertyStorage) {
        this.tuleapUserPropertyStorage = tuleapUserPropertyStorage;
    }

    @Inject
    public void setUserAuthoritiesRetriever(UserAuthoritiesRetriever userAuthoritiesRetriever) {
        this.userAuthoritiesRetriever = userAuthoritiesRetriever;
    }

    @Inject
    public void setTuleapGroupHelper(TuleapGroupHelper tuleapGroupHelper) {
        this.tuleapGroupHelper = tuleapGroupHelper;
    }

    private void injectInstances() {
        if (this.pluginHelper == null ||
            this.authorizationCodeChecker == null ||
            this.accessTokenChecker == null ||
            this.IDTokenChecker == null ||
            this.gson == null ||
            this.authorizationCodeUrlBuilder == null ||
            this.accessTokenApi == null ||
            this.openIDClientApi == null ||
            this.tuleapUserPropertyStorage == null ||
            this.userAuthoritiesRetriever == null ||
            this.tuleapGroupHelper == null
        ) {
            Guice.createInjector(new TuleapOAuth2GuiceModule()).injectMembers(this);
        }
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }

    public String getTuleapUri() {
        TuleapConfiguration tuleapUric = this.pluginHelper.getConfiguration();
        String tuleapUri = tuleapUric.getDomainUrl();
        if (!StringUtils.isBlank(tuleapUri) && !tuleapUri.endsWith("/")) {
            tuleapUri = tuleapUri.concat("/");
        }
        return tuleapUri;
    }

    private void setClientSecret(String secretString) {
        this.clientSecret = Secret.fromString(secretString);
    }

    private TuleapOAuthClientConfiguration buildTuleapOAuthClientConfiguration() {
        return new TuleapOAuthClientConfiguration(
            this.clientId,
            this.clientSecret
        );
    }

    @Override
    public UserDetails loadUserByUsername2(String username) {
        this.injectInstances();

        final Authentication authenticatedUserSpringToken = this.pluginHelper.getCurrentUserAuthenticationToken();

        if (authenticatedUserSpringToken == null) {
            throw new UserMayOrMayNotExistException2("No access token found for user " + username);
        }

        if (!(authenticatedUserSpringToken instanceof TuleapAuthenticationToken)) {
            throw new UserMayOrMayNotExistException2("Unknown token type for user " + username);
        }

        final User user = this.pluginHelper.getUser(username);

        if (!(user != null && this.tuleapUserPropertyStorage.has(user))) {
            throw new UsernameNotFoundException("Could not find user " + username + " for Tuleap");
        }

        return new TuleapUserDetails(username);
    }

    @Override
    public GroupDetails loadGroupByGroupname2(String groupName, boolean fetchMembers) {
        this.injectInstances();

        final Authentication authenticatedUserSpringToken = this.pluginHelper.getCurrentUserAuthenticationToken();

        if (! this.tuleapGroupHelper.groupNameIsInTuleapFormat(groupName)) {
            throw new UsernameNotFoundException("Not a Tuleap Group");
        }

        if (authenticatedUserSpringToken == null) {
            throw new UserMayOrMayNotExistException2("No access token found for user");
        }

        if (!(authenticatedUserSpringToken instanceof TuleapAuthenticationToken)) {
            throw new UserMayOrMayNotExistException2("Unknown token type for user");
        }

        final TuleapAuthenticationToken tuleapAuthenticationToken = (TuleapAuthenticationToken) authenticatedUserSpringToken;

        if (this.tuleapGroupHelper.groupExistsOnTuleapServer(groupName, tuleapAuthenticationToken, this.buildTuleapOAuthClientConfiguration())) {
            return new TuleapGroupDetails(groupName);
        }

        throw new UsernameNotFoundException("Could not find group " + groupName + " for Tuleap");
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {

            public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
                if (authentication instanceof TuleapAuthenticationToken) {
                    return authentication;
                }
                throw new BadCredentialsException(
                    "Unexpected authentication type: " + authentication);
            }
        });
    }

    @Override
    public String getLoginUrl() {
        return LOGIN_URL;
    }

    @Override
    protected String getPostLogOutUrl2(StaplerRequest2 req, Authentication auth) {
        this.injectInstances();

        auth.setAuthenticated(false);
        Jenkins jenkins = this.getJenkinsInstance();
        if (jenkins.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl2(req, auth);
        }
        return req.getContextPath() + "/" + TuleapLogoutAction.REDIRECT_ON_LOGOUT;
    }

    public HttpResponse doCommenceLogin(StaplerRequest2 request, @QueryParameter String from, @Header("Referer") final String referer) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        this.injectInstances();
        final String authorizationCodeUri = this.authorizationCodeUrlBuilder.buildRedirectUrlAndStoreSessionAttribute(
            request,
            this.getTuleapUri(),
            this.clientId
        );

        if (from != null) {
            request.getSession().setAttribute(REDIRECT_TO_SESSION_ATTRIBUTE, from);
        } else if (referer != null) {
            request.getSession().setAttribute(REDIRECT_TO_SESSION_ATTRIBUTE, referer);
        }
        return new HttpRedirect(authorizationCodeUri);
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE") // see https://github.com/spotbugs/spotbugs/issues/651
    public HttpResponse doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) throws IOException, JwkException, ServletException {
        if (!this.authorizationCodeChecker.checkAuthorizationCode(request)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        final String codeVerifier = (String) request.getSession().getAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE);
        final String authorizationCode = request.getParameter("code");

        AccessToken accessToken = this.accessTokenApi.getAccessToken(
            codeVerifier,
            authorizationCode,
            this.clientId,
            this.clientSecret
        );

        if (!this.accessTokenChecker.checkResponseBody(accessToken)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        List<Jwk> jwks = this.openIDClientApi.getSigningKeys();
        DecodedJWT idToken = JWT.decode(accessToken.getIdToken());

        this.IDTokenChecker.checkPayloadAndSignature(idToken, jwks, this.getTuleapUri(), this.clientId, request);

        UserInfo userInfo = this.openIDClientApi.getUserInfo(accessToken);

        String jenkinsInstanceRootUrl = this.getJenkinsInstance().getRootUrl();

        if (!this.userInfoChecker.checkUserInfoResponseBody(userInfo, idToken)) {
            return HttpResponses.redirectTo(jenkinsInstanceRootUrl + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        String redirectTo = (String) request.getSession().getAttribute(REDIRECT_TO_SESSION_ATTRIBUTE);

        this.authenticateAsTuleapUser(request, userInfo, accessToken);

        if (redirectTo != null && (Util.isSafeToRedirectTo(redirectTo) || (jenkinsInstanceRootUrl != null && redirectTo.startsWith(jenkinsInstanceRootUrl)))) {
            return HttpResponses.redirectTo(redirectTo);
        }

        return HttpResponses.redirectToContextRoot();
    }

    private Jenkins getJenkinsInstance() {
        return this.pluginHelper.getJenkinsInstance();
    }

    private void authenticateAsTuleapUser(StaplerRequest2 request, UserInfo userInfo, AccessToken accessToken) throws IOException {
        final TuleapUserDetails tuleapUserDetails = new TuleapUserDetails(userInfo.getUsername());
        tuleapUserDetails.addAuthority(SecurityRealm.AUTHENTICATED_AUTHORITY2);

        this.userAuthoritiesRetriever
            .getAuthoritiesForUser(accessToken)
            .forEach(tuleapUserDetails::addTuleapAuthority);

        TuleapAuthenticationToken tuleapAuth = new TuleapAuthenticationToken(
            tuleapUserDetails,
            accessToken
        );

        HttpSession session = request.getSession(false);
        if (session != null) {
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);

        SecurityContextHolder.getContext().setAuthentication(tuleapAuth);
        User tuleapUser = User.current();
        if (tuleapUser == null) {
            throw new UsernameNotFoundException("User not found");
        }

        tuleapUser.setFullName(userInfo.getName());

        if (!tuleapUser.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
            tuleapUser.addProperty(new Mailer.UserProperty(userInfo.getEmail()));
        }

        this.tuleapUserPropertyStorage.save(tuleapUser);

        SecurityListener.fireAuthenticated2(tuleapUserDetails);
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "Tuleap Authentication";
        }

        @POST
        public FormValidation doCheckTuleapUri(@QueryParameter String tuleapUri) {
            final PluginHelper pluginHelper = Guice.createInjector(new TuleapOAuth2GuiceModule()).getInstance(PluginHelper.class);
            if (pluginHelper.isHttpsUrl(tuleapUri)) {
                return FormValidation.ok();
            }
            return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckUrl());
        }

        @POST
        public FormValidation doCheckClientId(@QueryParameter String clientId) {
            if (StringUtils.isBlank(clientId)) {
                return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdEmpty());
            }

            if (!clientId.matches("^(tlp-client-id-)\\d+$")) {
                return FormValidation.error(Messages.TuleapSecurityRealmDescriptor_CheckClientIdFormat());
            }
            return FormValidation.ok();
        }

        @Override
        public String getHelpFile() {
            return "/plugin/tuleap-oauth/helpTuleapSecurityRealm/helpTuleapRealm/help.html";
        }
    }
}
