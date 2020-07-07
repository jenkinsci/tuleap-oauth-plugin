package io.jenkins.plugins.tuleap_oauth;

import hudson.util.Secret;

public class TuleapOAuthClientConfiguration {
    private final String clientId;
    private final Secret clientSecret;

    public TuleapOAuthClientConfiguration (
        final String clientId,
        final Secret clientSecret
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public Secret getClientSecret() {
        return clientSecret;
    }
}
