package com.signicat.hackathon.sample.enterprise;

import java.io.IOException;
import java.net.URI;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

public class UserInfoEndpointExamples {

    /**
     * Example for how to send a UserInfo Request.
     *
     * @param accessToken The Bearer Access Token received in the Token response.
     * @return The UserInfo claims.
     * @throws IOException If an I/O error occurs while sending the UserInfo request.
     * @throws ParseException If the response cannot be parsed as a UserInfo response.
     */
    public UserInfo exchangeAccessTokenForUserInfo(BearerAccessToken accessToken) throws IOException, ParseException {
        // Signicat's OIDC UserInfo endpoint.
        URI userInfoEndpointUri = URI.create("https://preprod.signicat.com/oidc/userinfo");

        // Create the UserInfo request using the bearer access token received in the Token response.
        UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpointUri, accessToken);

        // Send the UserInfo request.
        UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());

        if (!userInfoResponse.indicatesSuccess()) {
            // UserInfo request was not successful.
            UserInfoErrorResponse errorResponse = userInfoResponse.toErrorResponse();
            throw new RuntimeException("Received User Info Error response: " + errorResponse.getErrorObject().toJSONObject());
        }

        // UserInfo request was successful.
        UserInfoSuccessResponse successResponse = userInfoResponse.toSuccessResponse();

        // Return the UserInfo claims.
        return successResponse.getUserInfo();
    }
}
