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
import org.junit.Before;
import org.junit.Test;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;

import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.*;

public class IDTokenCheckerImplTest {

    private static final String ISSUER = "https://success.example.com";
    private static final String NONCE = "1234_nonce";
    private static final String AUDIENCE = "B35S";

    private PluginHelper pluginHelper;
    private OpenIDClientApi openIDClientApi;

    @Before
    public void setUp() {
        this.pluginHelper = mock(PluginHelper.class);
        this.openIDClientApi = mock(OpenIDClientApi.class);
    }

    @Test(expected = IncorrectClaimException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenTheIssuerIsNotExpected() throws InvalidPublicKeyException, IOException {
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

        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }

    @Test(expected = AlgorithmMismatchException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenTheAlgorithmIsNotExpected() throws InvalidPublicKeyException, IOException {
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

        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }

    @Test(expected = IncorrectClaimException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenNonceValueIsNotExpected() throws InvalidPublicKeyException, IOException {
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
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, audience, request);
    }

    @Test(expected = InvalidPublicKeyException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256ValidKey() throws InvalidPublicKeyException, IOException {
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
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }

    @Test(expected = InvalidPublicKeyException.class)
    public void testPayloadAndSignatureThrowsExceptionWhenThereIsNoRS256Key() throws InvalidPublicKeyException, IOException {
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
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }

    @Test(expected = IncorrectClaimException.class)
    public void testPayloadReturnsExceptionWhenUnexpectedAudience() throws InvalidPublicKeyException, IOException {
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
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, audience, request);
    }

    @Test(expected = MissingClaimException.class)
    public void testPayloadReturnsExceptionWhenThereIsNoIssuer() throws InvalidPublicKeyException, IOException {
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

        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER, AUDIENCE, request);
    }

    @Test(expected = MissingClaimException.class)
    public void testPayloadReturnsExceptionWhenThereIsNoAudience() throws InvalidPublicKeyException, IOException {
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
        jwtChecker.checkPayloadAndSignature(jwt, jwkList, ISSUER , audience, request);
    }

    @Test
    public void testPayloadAndSignatureAreOk() throws InvalidPublicKeyException, IOException {
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
