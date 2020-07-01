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
import hudson.security.UserMayOrMayNotExistException;
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
import io.jenkins.plugins.tuleap_oauth.helper.UserAuthoritiesRetriever;
import io.jenkins.plugins.tuleap_server_configuration.TuleapConfiguration;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import okhttp3.*;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.verb.POST;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class TuleapSecurityRealm extends SecurityRealm {

    private static final Logger LOGGER = Logger.getLogger(TuleapSecurityRealm.class.getName());

    private String clientId;
    private Secret clientSecret;

    private static final String LOGIN_URL = "securityRealm/commenceLogin";
    public static final String REDIRECT_URI = "securityRealm/finishLogin";

    public static final String CODE_VERIFIER_SESSION_ATTRIBUTE = "code_verifier";
    public static final String STATE_SESSION_ATTRIBUTE = "state";
    public static final String JENKINS_REDIRECT_URI_ATTRIBUTE = "redirect_uri";
    public static final String NONCE_ATTRIBUTE = "nonce";

    public static final String AUTHORIZATION_ENDPOINT = "oauth2/authorize?";

    public static final String SCOPES = "read:project read:user_membership openid profile email";
    public static final String CODE_CHALLENGE_METHOD = "S256";

    private AuthorizationCodeChecker authorizationCodeChecker;
    private PluginHelper pluginHelper;
    private AccessTokenChecker accessTokenChecker;
    private Gson gson;
    private IDTokenChecker IDTokenChecker;
    private UserInfoChecker userInfoChecker;
    private TuleapAuthorizationCodeUrlBuilder authorizationCodeUrlBuilder;
    private TuleapUserPropertyStorage tuleapUserPropertyStorage;
    private UserAuthoritiesRetriever userAuthoritiesRetriever;

    private AccessTokenApi accessTokenApi;
    private OpenIDClientApi openIDClientApi;

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
            this.userAuthoritiesRetriever == null
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

    @Override
    public UserDetails loadUserByUsername(String username) {
        this.injectInstances();

        final Authentication authenticatedUserAcegiToken = this.pluginHelper.getCurrentUserAuthenticationToken();

        if (authenticatedUserAcegiToken == null) {
            throw new UserMayOrMayNotExistException("No access token found for user " + username);
        }

        if (!(authenticatedUserAcegiToken instanceof TuleapAuthenticationToken)) {
            throw new UserMayOrMayNotExistException("Unknown token type for user " + username);
        }

        final User user = this.pluginHelper.getUser(username);

        if (!(user != null && this.tuleapUserPropertyStorage.has(user))) {
            throw new UsernameNotFoundException("Could not find user " + username + " for Tuleap");
        }

        return new TuleapUserDetails(username);
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        final Authentication authenticatedUserAcegiToken = this.pluginHelper.getCurrentUserAuthenticationToken();

        if (authenticatedUserAcegiToken == null) {
            throw new UserMayOrMayNotExistException("No access token found for user");
        }

        if (!(authenticatedUserAcegiToken instanceof TuleapAuthenticationToken)) {
            throw new UserMayOrMayNotExistException("Unknown token type for user");
        }

        final TuleapAuthenticationToken tuleapAuthenticationToken = (TuleapAuthenticationToken) authenticatedUserAcegiToken;

        if (! this.tokenHasTuleapGroup(tuleapAuthenticationToken, groupName)) {
            throw new UsernameNotFoundException("Group " + groupName + " not found for current Tuleap user");
        }

        return new TuleapGroupDetails(groupName);
    }

    private Boolean tokenHasTuleapGroup(TuleapAuthenticationToken token, String groupName) {
        return token
            .getTuleapUserDetails()
            .getTuleapAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList())
            .contains(groupName);
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
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        this.injectInstances();

        auth.setAuthenticated(false);
        Jenkins jenkins = this.getJenkinsInstance();
        if (jenkins.hasPermission(Jenkins.READ)) {
            return super.getPostLogOutUrl(req, auth);
        }
        return req.getContextPath() + "/" + TuleapLogoutAction.REDIRECT_ON_LOGOUT;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        this.injectInstances();
        final String authorizationCodeUri = this.authorizationCodeUrlBuilder.buildRedirectUrlAndStoreSessionAttribute(
            request,
            this.getTuleapUri(),
            this.clientId
        );
        return new HttpRedirect(authorizationCodeUri);
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE") // see https://github.com/spotbugs/spotbugs/issues/651
    public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) throws IOException, JwkException, ServletException {
        if (!this.authorizationCodeChecker.checkAuthorizationCode(request)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        final String codeVerifier = (String) request.getSession().getAttribute(CODE_VERIFIER_SESSION_ATTRIBUTE);
        final String authorizationCode = request.getParameter("code");

        AccessToken accessToken = this.accessTokenApi.getAccessToken(codeVerifier, authorizationCode, this.clientId, this.clientSecret);

        if (!this.accessTokenChecker.checkResponseBody(accessToken)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        List<Jwk> jwks = this.openIDClientApi.getSigningKeys();
        DecodedJWT idToken = JWT.decode(accessToken.getIdToken());

        this.IDTokenChecker.checkPayloadAndSignature(idToken, jwks, this.getTuleapUri(), this.clientId, request);

        UserInfo userInfo = this.openIDClientApi.getUserInfo(accessToken);

        if (!this.userInfoChecker.checkUserInfoResponseBody(userInfo, idToken)) {
            return HttpResponses.redirectTo(this.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR);
        }

        this.authenticateAsTuleapUser(request, userInfo, accessToken);

        return HttpResponses.redirectToContextRoot();
    }

    private ResponseBody getResponseBody(Response response) throws IOException {
        ResponseBody body = response.body();

        if (body == null) {
            LOGGER.log(Level.WARNING, "An error occurred");
            return null;
        }

        if (!response.isSuccessful()) {
            LOGGER.log(Level.WARNING, body.string());
            return null;
        }
        return body;
    }

    private Jenkins getJenkinsInstance() {
        return this.pluginHelper.getJenkinsInstance();
    }

    private void authenticateAsTuleapUser(StaplerRequest request, UserInfo userInfo, AccessToken accessToken) throws IOException {
        final TuleapUserDetails tuleapUserDetails = new TuleapUserDetails(userInfo.getUsername());
        tuleapUserDetails.addAuthority(SecurityRealm.AUTHENTICATED_AUTHORITY);

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

        SecurityListener.fireAuthenticated(tuleapUserDetails);
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
