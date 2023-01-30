package io.jenkins.plugins.tuleap_oauth.helper;

import io.jenkins.plugins.tuleap_api.client.ProjectApi;
import io.jenkins.plugins.tuleap_api.client.UserApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserAuthoritiesRetrieverTest {

    @Test
    public void itReturnsAListOfAuthoritiesMadeOfTuleapGroups() {
        final UserApi userApi = mock(UserApi.class);
        final AccessToken accessToken = mock(AccessToken.class);
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(mock(ProjectApi.class));
        final UserAuthoritiesRetriever userAuthoritiesRetriever = new UserAuthoritiesRetriever(userApi, tuleapGroupHelper);
        final UserGroup userGroup1 = mock(UserGroup.class);
        final UserGroup userGroup2 = mock(UserGroup.class);

        when(userGroup1.getProjectName()).thenReturn("use-me");
        when(userGroup2.getProjectName()).thenReturn("use-me");
        when(userGroup1.getGroupName()).thenReturn("project_members");
        when(userGroup2.getGroupName()).thenReturn("project_admins");

        when(userApi.getUserMembership(accessToken)).thenReturn(Arrays.asList(userGroup1, userGroup2));

        final List<GrantedAuthority> authorities = userAuthoritiesRetriever.getAuthoritiesForUser(accessToken);
        assertEquals(authorities.size(), 2);
        assertEquals(authorities.get(0).getAuthority(), "use-me#project_members");
        assertEquals(authorities.get(1).getAuthority(), "use-me#project_admins");
    }
}
