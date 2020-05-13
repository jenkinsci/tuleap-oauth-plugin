package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AccessTokenCheckerImplTest {


    @Test
    public void testResponseBodyReturnsFalseWhenBadTokenType() {
        AccessToken representation = mock(AccessToken.class);
        when(representation.getTokenType()).thenReturn("mac");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl();
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }


    @Test
    public void testResponseBodyReturnsTrueWhenAllChecksAreOk() {
        AccessToken representation = mock(AccessToken.class);
        when(representation.getTokenType()).thenReturn("bearer");
        when(representation.getExpiresIn()).thenReturn("1202424");
        when(representation.getIdToken()).thenReturn("ignseojseogjiosevjazfoaz");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl();
        assertTrue(accessTokenChecker.checkResponseBody(representation));
    }
}
