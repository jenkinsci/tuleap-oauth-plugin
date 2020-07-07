package io.jenkins.plugins.tuleap_oauth;

import hudson.security.GroupDetails;
import io.jenkins.plugins.tuleap_oauth.helper.TuleapGroupHelper;

public class TuleapGroupDetails extends GroupDetails {
    private final String groupName;

    public TuleapGroupDetails(final String groupName) {
        this.groupName = groupName;
    }

    @Override
    public String getName() {
        return this.groupName;
    }

    @Override
    public String getDisplayName() {
        return String.join(" / ", this.groupName.split(TuleapGroupHelper.GROUP_SEPARATOR));
    }
}
