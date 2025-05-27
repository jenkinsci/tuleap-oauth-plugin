package io.jenkins.plugins.tuleap_oauth;

import hudson.model.User;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsSessionRule;

import java.util.Objects;

import static org.junit.Assert.*;

public class TuleapUserPropertyStorageTest {
    private final TuleapUserPropertyStorage tuleapUserPropertyStorage = new TuleapUserPropertyStorage();

    @Rule
    public JenkinsSessionRule story = new JenkinsSessionRule();

    @Test
    public void correctBehavior() throws Throwable {
        story.then(j -> {
            User.getById("alice", true);

            assertFalse(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
            tuleapUserPropertyStorage.save(Objects.requireNonNull(User.getById("alice", false)));
            assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
        });
    }

    @Test
    public void correctBehaviorEvenAfterRestart() throws Throwable {
        story.then(j -> {
            User.getById("alice", true).save();

            assertFalse(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
            tuleapUserPropertyStorage.save(Objects.requireNonNull(User.getById("alice", false)));
            assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
        });
        story.then(j -> assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false)))));
    }
}
