package com.signicat.hackathon.sample.enterprise;

import java.io.IOException;
import java.net.URI;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

public class TokenEndpointExamples {

    /**
     * Example for how to send a Token Request.
     *
     * @param code The authorization code extracted from the Authentication response.
     * @return A set of OIDC tokens, most notably an ID Token (which should be validated),
     * and a Bearer Access Token, which we can use to fetch claims from the UserInfo endpoint.
     * @throws IOException If an I/O error occurs while sending the Token request.
     * @throws ParseException If the response cannot be parsed as a Token response.
     */
    public OIDCTokens exchangeAuthorizationCodeForTokens(AuthorizationCode code) throws IOException, ParseException {
        // Signicat's OIDC token endpoint.
        URI tokenEndpointUri = URI.create("https://preprod.signicat.com/oidc/token");

        // The redirect URI used for the authentication callback.
        // Note that the token request is server-to-server. The user is not actually being redirected at this stage.
        URI redirectUri = URI.create("https://service-provider.example/redirect");

        // Use the authorization code and redirect URI to create an Authorization Code Grant.
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, redirectUri);

        // The service provider's client ID.
        ClientID clientID = new ClientID("service-provider-clientID");

        // Client secret, known only by the service provider and Signicat.
        Secret clientSecret = new Secret("my-client-secret");

        // The client ID and client secret are used as credentials for the Token request.
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // Create the Token request.
        TokenRequest tokenRequest = new TokenRequest(tokenEndpointUri, clientAuth, codeGrant);

        // Send the token request.
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

        if (!tokenResponse.indicatesSuccess()) {
            // Token request was not successful.
            TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            throw new RuntimeException("Received Token Error response: " + errorResponse.getErrorObject().toJSONObject());
        }

        // Token request was successful.
        OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

        // The main tokens we are concerned with are the ID Token and the Bearer Access Token.
        // The ID Token should be validated, and the Bearer Access Token is used to access the User Info endpoint.
        return successResponse.getOIDCTokens();
    }
}
