package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_api.client.UserApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

public class UserAuthoritiesRetriever {
    private final UserApi userApi;
    private final TuleapGroupHelper tuleapGroupHelper;

    @Inject
    public UserAuthoritiesRetriever(final UserApi userApi, final TuleapGroupHelper tuleapGroupHelper) {
        this.userApi = userApi;
        this.tuleapGroupHelper = tuleapGroupHelper;
    }

    public List<GrantedAuthority> getAuthoritiesForUser(final AccessToken accessToken) {
        final List<UserGroup> userGroups = this.userApi.getUserMembership(accessToken);

        return userGroups.stream()
            .map(userGroup -> new SimpleGrantedAuthority(this.tuleapGroupHelper.buildJenkinsName(userGroup)))
            .collect(Collectors.toList());
    }
}
