package io.jenkins.plugins.tuleap_oauth.helper;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import io.jenkins.plugins.tuleap_server_configuration.TuleapConfiguration;
import jenkins.model.Jenkins;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.commons.net.util.Base64;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PluginHelperImpl implements PluginHelper {

    private static Logger LOGGER = Logger.getLogger(PluginHelper.class.getName());

    private final static Integer RECOMMENDED_LENGTH = 32;

    public Jenkins getJenkinsInstance() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins not started");
        }
        return jenkins;
    }

    @Override
    public TuleapConfiguration getConfiguration() {
       return TuleapConfiguration.get();
    }

    @Override
    public String buildRandomBase64EncodedURLSafeString() {
        byte[] code = new byte[RECOMMENDED_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(code);
        return Base64.encodeBase64URLSafeString(code);
    }

    @Override
    public Algorithm getAlgorithm(Jwk jwk) throws InvalidPublicKeyException {
        return Algorithm.RSA256((RSAPublicKey)jwk.getPublicKey(),null);
    }

    @Override
    public boolean isHttpsUrl(String url) {
        return url.matches("^(https)://.*$");
    }

    @Override
    public ResponseBody getResponseBody(Response response) throws IOException {
        ResponseBody body = response.body();

        if (body == null) {
            LOGGER.log(Level.WARNING, "An error occurred, body is null");
            return null;
        }

        if (!response.isSuccessful()) {
            LOGGER.log(Level.WARNING, body.string());
            return null;
        }

        return body;
    }
}
