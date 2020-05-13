package io.jenkins.plugins.tuleap_oauth.checks;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.util.List;

public interface IDTokenChecker {
    void checkPayloadAndSignature(DecodedJWT jwt, List<Jwk> jwks, String issuer, String audience, StaplerRequest request) throws InvalidPublicKeyException, IOException;
}
