package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jenkins.plugins.tuleap_api.client.authentication.OpenIDClientApi;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import io.jenkins.plugins.tuleap_oauth.stubs.ClaimStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;

import javax.servlet.http.HttpSession;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class IDTokenCheckerImplTest {

    private static final String ISSUER = "https://success.example.com";
    private static final String NONCE = "1234_nonce";
    private static final String AUDIENCE = "B35S";

    private PluginHelper pluginHelper;
    private OpenIDClientApi openIDClientApi;

    @BeforeEach
    void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
        this.openIDClientApi = mock(OpenIDClientApi.class);
    }

    @Test
    void testPayloadAndSignatureThrowsExceptionWhenTheIssuerIsNotExpected() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn("https://fail.example.com");
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        assertThrows(IncorrectClaimException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request));
    }

    @Test
    void testPayloadAndSignatureThrowsExceptionWhenTheAlgorithmIsNotExpected() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("HS256");
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Collections.singletonList(key1);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        assertThrows(AlgorithmMismatchException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request));
    }

    @Test
    void testPayloadAndSignatureThrowsExceptionWhenNonceValueIsNotExpected() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Claim audClaim = ClaimStub.withStringValue(AUDIENCE);
        when(jwt.getClaim("aud")).thenReturn(audClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Collections.singletonList(key1);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        String audience = "B35S";
        assertThrows(IncorrectClaimException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, audience, request));
    }

    @Test
    void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256ValidKey() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        doThrow(SignatureVerificationException.class).when(algorithmKey1).verify(jwt);
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        doThrow(SignatureVerificationException.class).when(algorithmKey2).verify(jwt);
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        RSAPublicKey publicKey1 = mock(RSAPublicKey.class);
        when(key1.getPublicKey()).thenReturn(publicKey1);
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        String audience = "B35S";
        assertThrows(InvalidPublicKeyException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request));
    }

    @Test
    void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256Key() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        verify(algorithmKey1, never()).verify(jwt);
        Algorithm algorithmKey2 = mock(Algorithm.class);
        verify(algorithmKey2, never()).verify(jwt);
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("HS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("HS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        String audience = "B35S";
        assertThrows(InvalidPublicKeyException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request));
    }

    @Test
    void testPayloadReturnsExceptionWhenUnexpectedAudience() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Claim audClaim = ClaimStub.withStringValue(AUDIENCE);
        when(jwt.getClaim("aud")).thenReturn(audClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        String audience = "Bullit";
        assertThrows(IncorrectClaimException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, audience, request));
    }

    @Test
    void testPayloadReturnsExceptionWhenThereIsNoIssuer() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(null);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        assertThrows(MissingClaimException.class, () ->

            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request));
    }

    @Test
    void testPayloadReturnsExceptionWhenThereIsNoAudience() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);
        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);
        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);
        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);
        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");
        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");
        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);
        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);
        String audience = null;
        assertThrows(MissingClaimException.class, () ->
            jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, audience, request));
    }

    @Test
    void testPayloadAndSignatureAreOk() throws Exception {
        IDTokenCheckerImpl jwtChecker = new IDTokenCheckerImpl(this.pluginHelper, this.openIDClientApi);

        when(this.openIDClientApi.getProviderIssuer()).thenReturn(ISSUER);

        DecodedJWT jwt = mock(DecodedJWT.class);
        when(jwt.getAlgorithm()).thenReturn("RS256");
        when(jwt.getAudience()).thenReturn(Collections.singletonList("B35S"));

        Claim issClaim = ClaimStub.withStringValue(ISSUER);
        when(jwt.getClaim("iss")).thenReturn(issClaim);

        Claim nonceClaim = ClaimStub.withStringValue(NONCE);
        when(jwt.getClaim("nonce")).thenReturn(nonceClaim);

        Claim audClaim = ClaimStub.withStringValue(AUDIENCE);
        when(jwt.getClaim("aud")).thenReturn(audClaim);

        Claim claim = ClaimStub.withStringValue("4485");
        when(jwt.getClaim("exp")).thenReturn(claim);
        when(jwt.getClaim("nbf")).thenReturn(claim);
        when(jwt.getClaim("iat")).thenReturn(claim);


        Algorithm algorithmKey1 = mock(Algorithm.class);
        when(algorithmKey1.getName()).thenReturn("RS256");
        Algorithm algorithmKey2 = mock(Algorithm.class);
        when(algorithmKey2.getName()).thenReturn("RS256");

        Jwk key1 = Mockito.mock(Jwk.class);
        when(key1.getAlgorithm()).thenReturn("RS256");
        Jwk key2 = Mockito.mock(Jwk.class);
        when(key2.getAlgorithm()).thenReturn("RS256");

        List<Jwk> jwkList = Arrays.asList(key1, key2);
        when(this.pluginHelper.getAlgorithm(key1)).thenReturn(algorithmKey1);
        when(this.pluginHelper.getAlgorithm(key2)).thenReturn(algorithmKey2);

        StaplerRequest request = mock(StaplerRequest.class);
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("nonce")).thenReturn(NONCE);
        when(request.getSession()).thenReturn(session);

        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }
}
