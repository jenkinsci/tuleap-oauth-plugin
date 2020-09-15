package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_oauth.TuleapAuthenticationErrorAction;
import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import org.kohsuke.stapler.StaplerRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

public class TuleapAuthorizationCodeUrlBuilderImpl implements TuleapAuthorizationCodeUrlBuilder {

    private static final Logger LOGGER = Logger.getLogger(TuleapAuthorizationCodeUrlBuilder.class.getName());

    private final PluginHelper pluginHelper;
    private final PKCECodeBuilder codeBuilder;

    @Inject
    public TuleapAuthorizationCodeUrlBuilderImpl(PluginHelper pluginHelper, PKCECodeBuilder codeBuilder) {
        this.pluginHelper = pluginHelper;
        this.codeBuilder = codeBuilder;
    }

    public String buildRedirectUrlAndStoreSessionAttribute(StaplerRequest request, String tuleapUri, String clientId) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        if (!this.pluginHelper.isHttpsUrl(tuleapUri)) {
            LOGGER.warning("The provided Tuleap URL is not in HTTPS");
            return this.pluginHelper.getJenkinsInstance().getRootUrl() + TuleapAuthenticationErrorAction.REDIRECT_ON_AUTHENTICATION_ERROR;
        }
        final String state = this.pluginHelper.buildRandomBase64EncodedURLSafeString();
        request.getSession().setAttribute(TuleapSecurityRealm.STATE_SESSION_ATTRIBUTE, state);

        final String rootUrl = this.pluginHelper.getJenkinsInstance().getRootUrl();

        final String redirectUri = URLEncoder.encode(rootUrl + TuleapSecurityRealm.REDIRECT_URI, UTF_8.name());
        final String codeVerifier = this.codeBuilder.buildCodeVerifier();
        final String codeChallenge = this.codeBuilder.buildCodeChallenge(codeVerifier);
        request.getSession().setAttribute(TuleapSecurityRealm.CODE_VERIFIER_SESSION_ATTRIBUTE, codeVerifier);

        final String nonce = this.pluginHelper.buildRandomBase64EncodedURLSafeString();
        request.getSession().setAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE, nonce);

        request.getSession().setAttribute(TuleapSecurityRealm.JENKINS_REDIRECT_URI_ATTRIBUTE, pluginHelper.getJenkinsInstance().getRootUrl() + TuleapSecurityRealm.REDIRECT_URI);

        return tuleapUri + TuleapSecurityRealm.AUTHORIZATION_ENDPOINT +
            "response_type=code" +
            "&client_id=" + URLEncoder.encode(clientId, UTF_8.name()) +
            "&redirect_uri=" + redirectUri +
            "&scope=" + URLEncoder.encode(TuleapSecurityRealm.SCOPES, UTF_8.name()) +
            "&state=" + state +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=" + URLEncoder.encode(TuleapSecurityRealm.CODE_CHALLENGE_METHOD, UTF_8.name()) +
            "&nonce=" + nonce;
    }
}
