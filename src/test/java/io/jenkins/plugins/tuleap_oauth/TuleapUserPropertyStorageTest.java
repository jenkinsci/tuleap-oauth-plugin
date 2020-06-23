package io.jenkins.plugins.tuleap_oauth;

import hudson.model.User;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.util.Objects;

import static org.junit.Assert.*;

public class TuleapUserPropertyStorageTest {
    private final TuleapUserPropertyStorage tuleapUserPropertyStorage = new TuleapUserPropertyStorage();

    @Rule
    public RestartableJenkinsRule j = new RestartableJenkinsRule();

    @Test
    public void correctBehavior() throws Exception {
        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                User.getById("alice", true);

                assertFalse(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                tuleapUserPropertyStorage.save(Objects.requireNonNull(User.getById("alice", false)));
                assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
            }
        });
    }

    @Test
    public void correctBehaviorEvenAfterRestart() throws Exception {
        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                User.getById("alice", true).save();

                assertFalse(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
                tuleapUserPropertyStorage.save(Objects.requireNonNull(User.getById("alice", false)));
                assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
            }
        });
        j.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                assertTrue(tuleapUserPropertyStorage.has(Objects.requireNonNull(User.getById("alice", false))));
            }
        });
    }
}
