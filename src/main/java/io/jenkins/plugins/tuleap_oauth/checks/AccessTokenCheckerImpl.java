package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.apache.commons.lang.StringUtils;

import java.util.logging.Level;
import java.util.logging.Logger;

public class AccessTokenCheckerImpl implements AccessTokenChecker {

    private static final Logger LOGGER = Logger.getLogger(AccessTokenChecker.class.getName());

    private static final String  ACCESS_TOKEN_TYPE = "bearer";

    @Override
    public boolean checkResponseBody(AccessToken accessToken){
        if (!accessToken.getTokenType().equals(ACCESS_TOKEN_TYPE)) {
            LOGGER.log(Level.WARNING, "Bad token type returned");
            return false;
        }
        return true;
    }
}
