package io.jenkins.plugins.tuleap_oauth;

import hudson.model.User;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TuleapUserPropertyStorage {
    private final Logger LOGGER =  Logger.getLogger(TuleapUserPropertyStorage.class.getName());

    public void save(User user) {
        try {
            user.addProperty(new TuleapUserProperty());
        } catch (IOException exception) {
            LOGGER.log(Level.WARNING, "Error while trying to save Tuleap user details for user: " + user.getId(), exception);
        }
    }

    public boolean has(User user) {
        return user.getProperty(TuleapUserProperty.class) != null;
    }
}
