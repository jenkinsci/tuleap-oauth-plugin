package io.jenkins.plugins.tuleap_oauth.helper;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import io.jenkins.plugins.tuleap_server_configuration.TuleapConfiguration;
import jenkins.model.Jenkins;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;

public interface PluginHelper {
    Jenkins getJenkinsInstance();
    TuleapConfiguration getConfiguration();
    String buildRandomBase64EncodedURLSafeString();
    Algorithm getAlgorithm(Jwk jwk) throws InvalidPublicKeyException;
    boolean isHttpsUrl(String url);
    ResponseBody getResponseBody(Response response) throws IOException;
}
