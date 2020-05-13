package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;

import java.util.logging.Logger;

public class UserInfoCheckerImpl implements UserInfoChecker {

    private static final Logger LOGGER = Logger.getLogger(UserInfoChecker.class.getName());

    @Override
    public boolean checkUserInfoResponseBody(UserInfo userInfo, DecodedJWT idToken) {
        if (!userInfo.getSubject().equals(idToken.getSubject())) {
            LOGGER.warning("Subject not expected");
            return false;
        }
        return true;
    }
}
