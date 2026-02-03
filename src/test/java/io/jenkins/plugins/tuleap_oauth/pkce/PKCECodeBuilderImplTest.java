package io.jenkins.plugins.tuleap_oauth.pkce;

import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class PKCECodeBuilderImplTest {

    private PluginHelper pluginHelper;

    @BeforeEach
    void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
    }

    @Test
    void testItShouldReturnAStringFromPluginHelper() {
        when(this.pluginHelper.buildRandomBase64EncodedURLSafeString()).thenReturn("123");

        assertEquals("123", this.pluginHelper.buildRandomBase64EncodedURLSafeString());
    }

    @Test
    void testItShouldBuildCorrectChallenge() throws NoSuchAlgorithmException {
        final PKCECodeBuilder codeBuilder = new PKCECodeBuilderImpl(this.pluginHelper);
        final String codeVerifier = "some code verifier";
        final String expectedChallenge = "m1GfpnTZ3GMybT0-zEFIFVtKZ5-__kYO0IxP_3lHoC4";

        assertEquals(expectedChallenge, codeBuilder.buildCodeChallenge(codeVerifier));
    }

}
