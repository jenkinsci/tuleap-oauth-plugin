package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.UserInfo;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class UserInfoCheckerImplTest {

    @Test
    public void testItReturnFalseWhenTheSubjectValueIsNotExpected() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getSubject()).thenReturn("123");

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("1510");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertFalse(userInfoChecker.checkUserInfoResponseBody(userInfo, idToken));
    }

    @Test
    public void testItReturnTrueIfTheBodyIsOk() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getSubject()).thenReturn("123");

        DecodedJWT idToken = mock(DecodedJWT.class);
        when(idToken.getSubject()).thenReturn("123");

        UserInfoCheckerImpl userInfoChecker = new UserInfoCheckerImpl();
        assertTrue(userInfoChecker.checkUserInfoResponseBody(userInfo, idToken));
    }
}
