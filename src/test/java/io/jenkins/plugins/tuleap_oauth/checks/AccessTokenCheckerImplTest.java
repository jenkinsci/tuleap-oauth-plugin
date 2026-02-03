package io.jenkins.plugins.tuleap_oauth.checks;

import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

class AccessTokenCheckerImplTest {

    @Test
    void testResponseBodyReturnsFalseWhenBadTokenType() {
        AccessToken representation = mock(AccessToken.class);
        when(representation.getTokenType()).thenReturn("mac");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl();
        assertFalse(accessTokenChecker.checkResponseBody(representation));
    }

    @Test
    void testResponseBodyReturnsTrueWhenAllChecksAreOkWithCapitalizedBearerTokenType() {
        responseBodyReturnsTrueWhenAllChecksAreOk("Bearer");
    }

    @Test
    void testResponseBodyReturnsTrueWhenAllChecksAreOkWithAllLowercaseBearerTokenType() {
        responseBodyReturnsTrueWhenAllChecksAreOk("bearer");
    }

    private void responseBodyReturnsTrueWhenAllChecksAreOk(String tokenType) {
        AccessToken representation = mock(AccessToken.class);
        when(representation.getTokenType()).thenReturn(tokenType);
        when(representation.getExpiresIn()).thenReturn("1202424");
        when(representation.getIdToken()).thenReturn("ignseojseogjiosevjazfoaz");

        AccessTokenCheckerImpl accessTokenChecker = new AccessTokenCheckerImpl();
        assertTrue(accessTokenChecker.checkResponseBody(representation));
    }
}
