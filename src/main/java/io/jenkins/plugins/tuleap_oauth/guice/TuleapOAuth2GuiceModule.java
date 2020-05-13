package io.jenkins.plugins.tuleap_oauth.guice;

import com.google.inject.AbstractModule;
import io.jenkins.plugins.tuleap_api.client.authentication.TuleapAuthenticationApiGuiceModule;
import io.jenkins.plugins.tuleap_oauth.checks.*;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelperImpl;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapAuthorizationCodeUrlBuilder;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapAuthorizationCodeUrlBuilderImpl;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilder;
import io.jenkins.plugins.tuleap_oauth.pkce.PKCECodeBuilderImpl;

public class TuleapOAuth2GuiceModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(AuthorizationCodeChecker.class).to(AuthorizationCodeCheckerImpl.class);
        bind(PluginHelper.class).to(PluginHelperImpl.class);
        bind(AccessTokenChecker.class).to(AccessTokenCheckerImpl.class);
        bind(PKCECodeBuilder.class).to(PKCECodeBuilderImpl.class);
        bind(IDTokenChecker.class).to(IDTokenCheckerImpl.class);
        bind(UserInfoChecker.class).to(UserInfoCheckerImpl.class);
        bind(TuleapAuthorizationCodeUrlBuilder.class).to(TuleapAuthorizationCodeUrlBuilderImpl.class);
        install(new TuleapAuthenticationApiGuiceModule());
    }
}
