package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_api.client.UserApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import io.jenkins.plugins.tuleap_oauth.TuleapGroupDetails;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import java.util.List;
import java.util.stream.Collectors;

public class UserAuthoritiesRetriever {
    private final UserApi userApi;

    @Inject
    public UserAuthoritiesRetriever(final UserApi userApi) {
        this.userApi = userApi;
    }

    public List<GrantedAuthority> getAuthoritiesForUser(final AccessToken accessToken) {
        final List<UserGroup> userGroups = this.userApi.getUserMembershipName(accessToken);

        return userGroups.stream()
            .map(userGroup -> new GrantedAuthorityImpl(userGroup.getProjectName() + TuleapGroupDetails.GROUP_SEPARATOR + userGroup.getGroupName()))
            .collect(Collectors.toList());
    }
}
