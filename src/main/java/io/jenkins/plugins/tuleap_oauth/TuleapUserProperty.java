package io.jenkins.plugins.tuleap_oauth;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.util.Secret;
import org.jenkinsci.Symbol;

public class TuleapUserProperty extends UserProperty {

    @Extension
    @Symbol("tuleapUserProperty")
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @Override
        public boolean isEnabled() {
            return false;
        }

        public UserProperty newInstance(User user) {
            return null;
        }
    }
}
