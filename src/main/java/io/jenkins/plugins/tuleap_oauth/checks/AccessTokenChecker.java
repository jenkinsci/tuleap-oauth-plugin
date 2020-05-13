package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import okhttp3.Response;

import java.io.IOException;

public interface AccessTokenChecker {
    boolean checkResponseBody(AccessToken AccessToken);
}
