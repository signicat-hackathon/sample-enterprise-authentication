package com.signicat.hackathon.sample.enterprise;

import java.net.URI;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;

public class AuthorizationEndpointExamples {

    /**
     * Example for how to create an Authentication request towards Signicat.
     *
     * @return The Authentication request as a URI. The authentication is initiated by directing the user to this URI.
     */
    public URI createAuthenticationRequest() {
        // Signicat's OIDC authorization endpoint.
        URI authEndpointUri = URI.create("https://preprod.signicat.com/oidc/authorization");

        // The service provider's client ID.
        ClientID clientID = new ClientID("service-provider-clientID");

        // The requested scope values.
        // Determines what sets of claims can be passed in the User Info response.
        Scope scope = new Scope("openid", "profile", "mitid");

        // The URI that the end-user will be redirected to after authentication.
        URI redirectUri = URI.create("https://service-provider.example/redirect");

        // We can decide which EID method will be used to authenticate the end-user using the ACR parameter.
        // Here we are using MitID authentication with CPR matching.
        ACR acr = new ACR("urn:signicat:oidc:method:mitid-cpr");


        // Prefilled parameters can be sent using the login_hint parameter.
        // Here we are prefilling the expected CPR number of the end-user.
        // This means they do not have to provide it manually themselves during the flow, assuming the prefilled value is correct.
        String loginHint = "subject-2805541111";

        // Random state value, used to bind the authentication request with the callback.
        // The state should be bound to the user-agent's session somehow, such as by binding the value to a session cookie.
        // This will help protect the end-user from CSRF attacks.
        State state = new State();

        // A nonce can be used in order to associate the OIDC client's session with the ID Token, mitigating replay attacks.
        // If used, the nonce should be stored server-side by the client, and later used when validating the ID Token.
        Nonce nonce = new Nonce();

        // Response type should be "code", since we are using the Authorization Code flow.
        ResponseType responseType = ResponseType.CODE;

        // Create the request.
        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectUri)
                .acrValues(Collections.singletonList(acr))
                .loginHint(loginHint)
                .state(state)
                .nonce(nonce)
                .endpointURI(authEndpointUri)
                .build();

        // The authentication will be initiated by sending the user to this URI.
        return authRequest.toURI();
    }

    /**
     * Example for how to create a signed Authentication request towards Signicat.
     * Prerequisite for using Authentic prefilled parameters in MitID.
     * @see <a href="https://developer.signicat.com/enterprise/docs/authentication/about-oidc.html#mitid-specifics-signing-authorisation-requests">Signicat developer docs</a>
     *
     * @param rsaKey The RSA key used to sign the request object of the Authentication request.
     * @return The Authentication request as a URI, with the signed request object as a query parameter.
     *
     * @throws JOSEException If signing the request object fails.
     */
    public URI createSignedAuthenticationRequest(RSAKey rsaKey) throws JOSEException {
        // Authentication request parameters, see createAuthenticationRequest() for in-depth explanations.
        URI authEndpointUri = URI.create("https://preprod.signicat.com/oidc/authorization");
        ClientID clientID = new ClientID("service-provider-clientID");
        Scope scope = new Scope("openid", "profile", "mitid");
        URI redirectUri = URI.create("https://service-provider.example/redirect");
        ACR acr = new ACR("urn:signicat:oidc:method:mitid-cpr");
        State state = new State();
        Nonce nonce = new Nonce();
        ResponseType responseType = ResponseType.CODE;

        // The main reason we may want to sign our Authentication request is in order to use "Authentic prefilled parameters".
        // There are certain parameters where Signicat needs to ensure that the request was created by the service provider's client.
        // In MitID, one of these parameters is the "reference text", which is a text displayed in the MitID Client UI to the end-user.
        // Signicat requires that prefilled values for the reference text are only sent in signed requests,
        // since otherwise a malicious agent could use it to present whichever text they want.
        String loginHint = "referenceText-My prefilled reference text";

        // We will sign the request object with RS256.
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;

        // Create the header for the signed request object.
        JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
                .keyID(rsaKey.getKeyID())
                .build();

        // Create the claims for the JWT request object.
        // The claims correspond to the parameters that would be used in an unsigned Authentication request.
        JWTClaimsSet requestObjectClaims = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectUri)
                .acrValues(Collections.singletonList(acr))
                .loginHint(loginHint)
                .state(state)
                .nonce(nonce)
                .build()
                .toJWTClaimsSet();

        SignedJWT requestObject = new SignedJWT(jwsHeader, requestObjectClaims);

        // Sign the request object with our private key.
        requestObject.sign(new RSASSASigner(rsaKey));

        // Create the actual Authentication request.
        // There are several parameters we need to include as plain query parameters, even though they are included
        // as claims in the request object.
        //
        // To comply with OAuth 2.0, the request still needs to contain parameters and values for 'response_type' and 'client_id'.
        // To be a valid OIDC Authentication Request, we also need to include the 'scope' parameter.
        AuthenticationRequest authRequest = new AuthenticationRequest.Builder(requestObject, clientID)
                .responseType(responseType)
                .scope(scope)
                .endpointURI(authEndpointUri)
                .build();

        // The authentication will be initiated by sending the user to this URI.
        return authRequest.toURI();
    }

    /**
     * Example for how to handle the callback from Signicat upon a completed authentication.
     *
     * @param callbackRequest The callback/redirect request from Signicat towards the client's redirect URI.
     * @param expectedState The state as provided in the original Authentication request.
     * @return The Authorization code. Can later be exchanged in a Token request for an Access Token and ID Token.
     *
     * @throws ParseException If the callback fails to parse as an Authentication response.
     */
    public AuthorizationCode handleAuthenticationCallback(HttpServletRequest callbackRequest, State expectedState) throws ParseException {
        // Parse the callback request as an Authentication Response.
        AuthenticationResponse response = AuthenticationResponseParser.parse(URI.create(callbackRequest.getRequestURI()));

        // Extract the "state" parameter from the callback request.
        State receivedState = State.parse(callbackRequest.getParameter("state"));

        // Validate that it matches the one we generated for the authentication request.
        if (!expectedState.equals(receivedState)) {
            throw new RuntimeException("Received state does not match expected state!");
        }

        if (!response.indicatesSuccess()) {
            // The authentication was not successful.
            AuthenticationErrorResponse errorResponse = response.toErrorResponse();
            throw new RuntimeException("Received Authentication Error response: " + errorResponse.getErrorObject().toJSONObject());
        }

        // The authentication was successful.
        AuthenticationSuccessResponse successResponse = response.toSuccessResponse();

        // Extract the Authorization Code from the success response.
        // It will later be used in a Token Request, to exchange for an Access Token and ID Token at
        // the token endpoint of Signicat's OIDC server.
        return successResponse.getAuthorizationCode();
    }
}
