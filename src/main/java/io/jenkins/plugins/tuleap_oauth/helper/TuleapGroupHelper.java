package io.jenkins.plugins.tuleap_oauth.helper;

import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_api.client.Project;
import io.jenkins.plugins.tuleap_api.client.ProjectApi;
import io.jenkins.plugins.tuleap_api.client.UserGroup;
import io.jenkins.plugins.tuleap_api.client.exceptions.ProjectNotFoundException;
import io.jenkins.plugins.tuleap_oauth.TuleapAuthenticationToken;
import io.jenkins.plugins.tuleap_oauth.TuleapOAuthClientConfiguration;
import org.apache.commons.lang.StringUtils;

import java.util.List;

public class TuleapGroupHelper {
    public static final String GROUP_SEPARATOR = "#";

    private final ProjectApi projectApi;

    @Inject
    public TuleapGroupHelper(final ProjectApi projectApi) {
        this.projectApi = projectApi;
    }

    public String buildJenkinsName(UserGroup userGroup) {
        return userGroup.getProjectName() + GROUP_SEPARATOR + userGroup.getGroupName();
    }

    public Boolean groupNameIsInTuleapFormat(String groupName) {
        return StringUtils.countMatches(groupName, GROUP_SEPARATOR) == 1;
    }

    public Boolean groupExistsOnTuleapServer(
        final String groupName,
        final TuleapAuthenticationToken authenticationToken,
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration
    ) {
        try {
            final List<UserGroup> groups = this.getGroupsForTuleapProject(
                this.getProjectFromTuleapServer(
                    this.getTuleapProjectName(groupName),
                    authenticationToken,
                    tuleapOAuthClientConfiguration
                ),
                authenticationToken,
                tuleapOAuthClientConfiguration
            );

            return groups.stream().anyMatch(userGroup -> userGroup.getGroupName().equals(this.getTuleapGroupName(groupName)));
        } catch (ProjectNotFoundException exception) {
            return false;
        }
    }

    private List<UserGroup> getGroupsForTuleapProject(
        final Project project,
        final TuleapAuthenticationToken authenticationToken,
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration
    ) {
        return this.projectApi.getProjectUserGroups(project.getId(), authenticationToken.getAccessToken());
    }

    private Project getProjectFromTuleapServer(
        final String shortName,
        final TuleapAuthenticationToken authenticationToken,
        final TuleapOAuthClientConfiguration tuleapOAuthClientConfiguration
    ) throws ProjectNotFoundException{
        return this.projectApi.getProjectByShortname(shortName, authenticationToken.getAccessToken());
    }

    private String getTuleapProjectName(String groupName) {
        return StringUtils.split(groupName, GROUP_SEPARATOR)[0];
    }

    private String getTuleapGroupName(String groupName) {
        return StringUtils.split(groupName, GROUP_SEPARATOR)[1];
    }
}
