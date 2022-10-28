package io.jenkins.plugins.tuleap_oauth.stubs;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;

import java.util.Date;
import java.util.List;
import java.util.Map;

public class ClaimStub implements Claim {

    private final String claimStringValue;
    private final Boolean isValueNull;

    private ClaimStub(String claimStringValue, Boolean isValueNull) {
        this.claimStringValue = claimStringValue;
        this.isValueNull = isValueNull;
    }

    @Override
    public boolean isNull() {
        return this.isValueNull;
    }

    @Override
    public boolean isMissing() {
        return false;
    }

    @Override
    public Boolean asBoolean() {
        return null;
    }

    @Override
    public Integer asInt() {
        return null;
    }

    @Override
    public Long asLong() {
        return null;
    }

    @Override
    public Double asDouble() {
        return null;
    }

    @Override
    public String asString() {
        return this.claimStringValue;
    }

    @Override
    public Date asDate() {
        return null;
    }

    @Override
    public <T> T[] asArray(Class<T> clazz) throws JWTDecodeException {
        return null;
    }

    @Override
    public <T> List<T> asList(Class<T> clazz) throws JWTDecodeException {
        return null;
    }

    @Override
    public Map<String, Object> asMap() throws JWTDecodeException {
        return null;
    }

    @Override
    public <T> T as(Class<T> clazz) throws JWTDecodeException {
        return null;
    }

    public static ClaimStub withStringValue(String value) {
        return new ClaimStub(value, false);
    }

    public static ClaimStub withNullClaimValue() {
        return new ClaimStub("", true);
    }
}
