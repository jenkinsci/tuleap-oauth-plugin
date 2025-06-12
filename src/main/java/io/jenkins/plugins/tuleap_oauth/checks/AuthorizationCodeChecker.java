package io.jenkins.plugins.tuleap_oauth.checks;

import org.kohsuke.stapler.StaplerRequest2;

public interface AuthorizationCodeChecker {
    boolean checkAuthorizationCode(StaplerRequest2 request);
}
