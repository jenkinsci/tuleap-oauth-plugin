package io.jenkins.plugins.tuleap_oauth;

import hudson.security.GroupDetails;

public class TuleapGroupDetails extends GroupDetails {
    public static final String GROUP_SEPARATOR = "#";

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
        return String.join(" / ", this.groupName.split(GROUP_SEPARATOR));
    }
}
