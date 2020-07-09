package io.jenkins.plugins.tuleap_oauth.pkce;

import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class PKCECodeBuilderImplTest {

    private PluginHelper pluginHelper;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
    }

    @Test
    public void testItShouldReturnAStringFromPluginHelper() {
        when(this.pluginHelper.buildRandomBase64EncodedURLSafeString()).thenReturn("123");

        assertEquals("123", this.pluginHelper.buildRandomBase64EncodedURLSafeString());
    }

    @Test
    public void testItShouldBuildCorrectChallenge() throws NoSuchAlgorithmException {
        final PKCECodeBuilder codeBuilder = new PKCECodeBuilderImpl(this.pluginHelper);
        final String codeVerifier = "some code verifier";
        final String expectedChallenge = "m1GfpnTZ3GMybT0-zEFIFVtKZ5-__kYO0IxP_3lHoC4";

        assertEquals(expectedChallenge, codeBuilder.buildCodeChallenge(codeVerifier));
    }

}
