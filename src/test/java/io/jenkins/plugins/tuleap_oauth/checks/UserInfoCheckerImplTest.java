package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

class UserInfoCheckerImplTest {

    @Test
    void testItReturnFalseWhenTheSubjectValueIsNotExpected() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getSubject()).thenReturn("123");

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("1510");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseBody(userInfo, idToken));
    }

    @Test
    void testItReturnFalseWhenTheUserIsInvalid() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getSubject()).thenReturn("1510");
        when(userInfo.isEmailVerified()).thenReturn(false);

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("1510");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseBody(userInfo, idToken));
    }

    @Test
    void testItReturnTrueIfTheBodyIsOk() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getSubject()).thenReturn("123");
        when(userInfo.isEmailVerified()).thenReturn(true);

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("123");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertTrue(userInfoChecker.checkUserInfoResponseBody(userInfo, idToken));
    }
}
