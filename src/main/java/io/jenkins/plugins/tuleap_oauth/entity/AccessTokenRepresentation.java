package io.jenkins.plugins.tuleap_oauth.entity;

import com.google.gson.annotations.SerializedName;
import io.jenkins.plugins.tuleap_api.client.authentication.AccessToken;

public class AccessTokenRepresentation implements AccessToken {
    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("token_type")
    private String tokenType;

    @SerializedName("expires_in")
    private String expiresIn;

    @SerializedName("id_token")
    private String idToken;

    @SerializedName("refresh_token")
    private String refreshToken;

    private AccessTokenRepresentation(
        String accessToken,
        String tokenType,
        String expiresIn,
        String idToken,
        String refreshToken
    ) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public String getIdToken() {
        return idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public static AccessTokenRepresentation buildFromAccessToken(AccessToken accessToken) {
        return new AccessTokenRepresentation(
            accessToken.getAccessToken(),
            accessToken.getTokenType(),
            accessToken.getExpiresIn(),
            accessToken.getIdToken(),
            accessToken.getRefreshToken()
        );
    }
}
