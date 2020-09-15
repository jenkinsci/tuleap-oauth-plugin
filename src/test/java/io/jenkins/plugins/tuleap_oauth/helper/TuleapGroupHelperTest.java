package io.jenkins.plugins.tuleap_oauth.helper;

import io.jenkins.plugins.tuleap_api.client.Project;
import io.jenkins.plugins.tuleap_api.client.ProjectApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessTokenApi;
import io.jenkins.plugins.tuleap_api.client.exceptions.ProjectNotFoundException;
import io.jenkins.plugins.tuleap_oauth.TuleapAuthenticationToken;
import io.jenkins.plugins.tuleap_oauth.TuleapOAuthClientConfiguration;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class TuleapGroupHelperTest {

    @Test
    public void itBuildsExpectedGroupNames() {
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(mock(ProjectApi.class));
        final UserGroup userGroup = mock(UserGroup.class);

        when(userGroup.getProjectName()).thenReturn("use-me");
        when(userGroup.getGroupName()).thenReturn("Contributors");

        assertEquals("use-me#Contributors", tuleapGroupHelper.buildJenkinsName(userGroup));
    }

    @Test
    public void itReturnsTrueIfGroupNameIsOfTuleapFormat() {
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(mock(ProjectApi.class));

        assertTrue(tuleapGroupHelper.groupNameIsInTuleapFormat("use-me#Contributors"));
        assertFalse(tuleapGroupHelper.groupNameIsInTuleapFormat("use-me#Contributors#test"));
        assertFalse(tuleapGroupHelper.groupNameIsInTuleapFormat("use-meContributorstest"));
    }

    @Test
    public void itReturnsFalseIfProjectDoesNotExistOnTuleapServer() throws ProjectNotFoundException {
        final ProjectApi projectApi = mock(ProjectApi.class);
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration = mock(TuleapOAuthClientConfiguration.class);
        final TuleapAuthenticationToken tuleapAuthenticationToken = mock(TuleapAuthenticationToken.class);
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(projectApi);

        when(projectApi.getProjectByShortname(anyString(), any())).thenThrow(new ProjectNotFoundException("whatever"));

        assertFalse(tuleapGroupHelper.groupExistsOnTuleapServer("whatever", tuleapAuthenticationToken, tuleapOAuthClientConfiguration));
    }

    @Test
    public void itReturnsFalsIfGroupIsNotPresentOnServer() throws ProjectNotFoundException {
        final ProjectApi projectApi = mock(ProjectApi.class);
        final Project project = mock(Project.class);
        final UserGroup userGroup1 = mock(UserGroup.class);
        final UserGroup userGroup2 = mock(UserGroup.class);
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration = mock(TuleapOAuthClientConfiguration.class);
        final TuleapAuthenticationToken tuleapAuthenticationToken = mock(TuleapAuthenticationToken.class);
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(projectApi);

        when(projectApi.getProjectByShortname(anyString(), any())).thenReturn(project);
        when(project.getId()).thenReturn(110);
        when(projectApi.getProjectUserGroups(eq(110), any())).thenReturn(Arrays.asList(
            userGroup1,
            userGroup2
        ));
        when(userGroup1.getGroupName()).thenReturn("Contributors");
        when(userGroup2.getGroupName()).thenReturn("project_members");

        assertFalse(tuleapGroupHelper.groupExistsOnTuleapServer("use-me#whatever", tuleapAuthenticationToken, tuleapOAuthClientConfiguration));
    }

    @Test
    public void itReturnsTrueIfGroupIsPresentOnServer() throws ProjectNotFoundException {
        final ProjectApi projectApi = mock(ProjectApi.class);
        final Project project = mock(Project.class);
        final UserGroup userGroup1 = mock(UserGroup.class);
        final UserGroup userGroup2 = mock(UserGroup.class);
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration = mock(TuleapOAuthClientConfiguration.class);
        final TuleapAuthenticationToken tuleapAuthenticationToken = mock(TuleapAuthenticationToken.class);
        final TuleapGroupHelper tuleapGroupHelper = new TuleapGroupHelper(projectApi);

        when(projectApi.getProjectByShortname(anyString(), any())).thenReturn(project);
        when(project.getId()).thenReturn(110);
        when(projectApi.getProjectUserGroups(eq(110), any())).thenReturn(Arrays.asList(
            userGroup1,
            userGroup2
        ));
        when(userGroup1.getGroupName()).thenReturn("Contributors");
        when(userGroup2.getGroupName()).thenReturn("project_members");

        assertTrue(tuleapGroupHelper.groupExistsOnTuleapServer("use-me#Contributors", tuleapAuthenticationToken, tuleapOAuthClientConfiguration));
    }
}
