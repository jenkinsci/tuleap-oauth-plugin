package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;

public interface AccessTokenChecker {
    boolean checkResponseBody(AccessToken AccessToken);
}
