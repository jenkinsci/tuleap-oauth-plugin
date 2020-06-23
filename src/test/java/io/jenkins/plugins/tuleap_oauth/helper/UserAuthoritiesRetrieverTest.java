package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.common.collect.ImmutableList;
import io.jenkins.plugins.tuleap_api.client.UserApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.acegisecurity.GrantedAuthority;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserAuthoritiesRetrieverTest {

    @Test
    public void itReturnsAListOfAuthoritiesMadeOfTuleapGroups() {
        final UserApi userApi = mock(UserApi.class);
        final AccessToken accessToken = mock(AccessToken.class);
        final UserAuthoritiesRetriever userAuthoritiesRetriever = new UserAuthoritiesRetriever(userApi);
        final UserGroup userGroup1 = mock(UserGroup.class);
        final UserGroup userGroup2 = mock(UserGroup.class);

        when(userGroup1.getProjectName()).thenReturn("use-me");
        when(userGroup2.getProjectName()).thenReturn("use-me");
        when(userGroup1.getGroupName()).thenReturn("project_members");
        when(userGroup2.getGroupName()).thenReturn("project_admins");

        when(userApi.getUserMembershipName(accessToken)).thenReturn(ImmutableList.of(userGroup1,userGroup2));

        final List<GrantedAuthority> authorities = userAuthoritiesRetriever.getAuthoritiesForUser(accessToken);
        assertEquals(authorities.size(), 2);
        assertEquals(authorities.get(0).getAuthority(), "use-me#project_members");
        assertEquals(authorities.get(1).getAuthority(), "use-me#project_admins");
    }
}
