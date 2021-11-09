package com.signicat.hackathon.sample.enterprise;

import java.net.MalformedURLException;
import java.net.URL;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class IDTokenValidationExamples {

    /**
     * Example for how to validate an ID Token.
     *
     * @param idToken The ID Token, extracted from the Token response.
     * @param expectedNonce The nonce as provided in the original Authentication request.
     * @return The validated claims set of the ID Token.
     *
     * @throws MalformedURLException If the JWKs URL is malformed.
     * @throws BadJOSEException If the signature or claims of the ID Token are invalid.
     * @throws JOSEException If an internal processing exception occurs while validating the ID Token.
     */
    public IDTokenClaimsSet validateIDToken(JWT idToken, Nonce expectedNonce) throws MalformedURLException, BadJOSEException, JOSEException {
        // We expect the token to have been issued by Signicat's OIDC server.
        Issuer expectedIssuer = new Issuer("https://preprod.signicat.com/oidc");

        // We expect the token to have been issued with our client ID as the audience.
        ClientID expectedAudience = new ClientID("service-provider-clientID");

        // We expect the token to have been signed using RS256 as the signing algorithm.
        JWSAlgorithm expectedJwsAlg = JWSAlgorithm.RS256;

        // In order to verify the signature, we must retrieve Signicat's public JWK set.
        // We expect the token to have been signed by the private key corresponding to one of the
        // public JWKs hosted on Signicat's JWKS endpoint.
        URL jwksUri = new URL("https://preprod.signicat.com/oidc/jwks.json");

        // Create a validator expecting a signed ID Token.
        IDTokenValidator validator = new IDTokenValidator(expectedIssuer, expectedAudience, expectedJwsAlg, jwksUri);

        // Validate the ID Token.
        /*
         * The following operations are performed:
         *
         * 1. Check that the JWS algorithm used to sign the ID Token matches the expected one.
         * 2. Validate the ID Token signature using one of the keys from Signicat's public JWK set.
         * 3. Check that the token issuer and audience match their expected values.
         * 4. Check that the current system time is between the 'issued at' and 'expiration' time of the ID Token.
         * 5. Check that the ID Token's nonce matches the one we used in the Authentication request.
         */
        return validator.validate(idToken, expectedNonce);
    }
}
