package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.inject.Inject;
import io.jenkins.plugins.tuleap_api.client.authentication.OpenIDClientApi;
import io.jenkins.plugins.tuleap_oauth.TuleapSecurityRealm;
import io.jenkins.plugins.tuleap_oauth.helper.PluginHelper;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.StaplerRequest;

import java.util.List;

public class IDTokenCheckerImpl implements IDTokenChecker {

    public static final String ALGORITHM = "RS256";

    private static final int ACCEPTED_LEEWAY_IN_SECONDS = 10;

    private final PluginHelper pluginHelper;
    private final OpenIDClientApi openIDClientApi;

    @Inject
    public IDTokenCheckerImpl(PluginHelper pluginHelper, OpenIDClientApi openIDClientApi) {
        this.pluginHelper = pluginHelper;
        this.openIDClientApi = openIDClientApi;
    }

    @Override
    public void checkPayloadAndSignature(
        DecodedJWT idToken,
        List<Jwk> jwks,
        String tuleapUri,
        String audience,
        StaplerRequest request
    ) throws InvalidPublicKeyException {
        String expectedIssuer = this.openIDClientApi.getProviderIssuer();

        if (StringUtils.isBlank(expectedIssuer)) {
            throw new InvalidClaimException("The issuer claim is blank or null");
        }

        String expectedNonce = (String) request.getSession().getAttribute(TuleapSecurityRealm.NONCE_ATTRIBUTE);

        for (Jwk jwk : jwks) {
            if (jwk.getAlgorithm().equals(ALGORITHM)) {
                try {
                    Algorithm algorithm = this.pluginHelper.getAlgorithm(jwk);
                    JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer(expectedIssuer)
                        .withAudience(audience)
                        .acceptLeeway(ACCEPTED_LEEWAY_IN_SECONDS)
                        .withClaim(TuleapSecurityRealm.NONCE_ATTRIBUTE, expectedNonce)
                        .build();

                    if (StringUtils.isBlank(audience)) {
                        throw new InvalidClaimException("The audience claim is blank or null");
                    }

                    verifier.verify(idToken);
                    return;
                } catch (SignatureVerificationException | InvalidPublicKeyException e) {
                    //The key does not match
                }
            }
        }
        throw new InvalidPublicKeyException("No valid RS256 Key found", null);
    }
}
