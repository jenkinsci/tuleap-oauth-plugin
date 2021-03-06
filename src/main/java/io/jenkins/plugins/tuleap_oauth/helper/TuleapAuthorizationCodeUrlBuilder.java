package io.jenkins.plugins.tuleap_oauth.helper;

import org.kohsuke.stapler.StaplerRequest;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public interface TuleapAuthorizationCodeUrlBuilder {
    String buildRedirectUrlAndStoreSessionAttribute(StaplerRequest request, String  tuleapUri, String clientId) throws UnsupportedEncodingException, NoSuchAlgorithmException;
}
