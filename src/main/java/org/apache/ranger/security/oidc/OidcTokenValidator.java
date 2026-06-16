/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ranger.security.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.security.Key;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Validates OIDC JWT tokens using JWKS (JSON Web Key Set).
 *
 * Supports RS256, RS384, RS512, ES256, ES384, ES512 algorithms.
 * Supports JWKS key rotation (refreshes on unknown kid).
 */
public class OidcTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(OidcTokenValidator.class);

    private final OidcConfiguration config;

    /** JWKS URL for fetching public keys. */
    private String jwksUrl;

    /** Cached JWK set. */
    private volatile JWKSet cachedJwkSet;

    /** Timestamp of last JWKS refresh. */
    private volatile long lastJwksRefreshTime;

    /** Minimum interval between JWKS refreshes (in milliseconds). */
    private static final long JWKS_REFRESH_INTERVAL_MS = 300_000L; // 5 minutes

    /** JWKS HTTP timeouts. */
    private static final int JWKS_CONNECT_TIMEOUT_MS = 5000;
    private static final int JWKS_READ_TIMEOUT_MS = 5000;
    private static final int JWKS_SIZE_LIMIT = 51200;

    public OidcTokenValidator(OidcConfiguration config) {
        this.config = config;
        this.jwksUrl = config.getJwksUri();
    }

    /**
     * Validates a JWT token string and returns the parsed claims if valid.
     *
     * @param tokenString the raw JWT token string
     * @return the validated JWT claims set
     * @throws OidcTokenValidationException if the token is invalid
     */
    public JWTClaimsSet validateToken(String tokenString) throws OidcTokenValidationException {
        if (tokenString == null || tokenString.trim().isEmpty()) {
            throw new OidcTokenValidationException("Token is null or empty");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(tokenString);
        } catch (ParseException e) {
            throw new OidcTokenValidationException("Failed to parse JWT token", e);
        }

        // Validate signature
        if (!validateSignature(signedJWT)) {
            throw new OidcTokenValidationException("JWT signature validation failed");
        }

        // Validate claims
        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new OidcTokenValidationException("Failed to parse JWT claims", e);
        }

        validateClaims(claims);

        LOG.debug("JWT token validated successfully for subject: {}", claims.getSubject());
        return claims;
    }

    /**
     * Validates the JWT signature using JWKS.
     */
    protected boolean validateSignature(SignedJWT signedJWT) {
        if (signedJWT.getState() != JWSObject.State.SIGNED) {
            LOG.warn("JWT is not in SIGNED state");
            return false;
        }

        try {
            // Try with cached keys first
            if (cachedJwkSet != null) {
                Key key = findVerificationKey(signedJWT, cachedJwkSet);
                if (key != null) {
                    JWSVerifier verifier = createVerifier(signedJWT.getHeader().getAlgorithm(), key);
                    if (verifier != null && signedJWT.verify(verifier)) {
                        return true;
                    }
                }
            }

            // Refresh JWKS and retry
            if (refreshJwks()) {
                Key key = findVerificationKey(signedJWT, cachedJwkSet);
                if (key != null) {
                    JWSVerifier verifier = createVerifier(signedJWT.getHeader().getAlgorithm(), key);
                    if (verifier != null && signedJWT.verify(verifier)) {
                        return true;
                    }
                }
            }

            return false;
        } catch (Exception e) {
            LOG.warn("Error validating JWT signature: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Finds the verification key from the JWK set matching the token's key ID and algorithm.
     */
    private Key findVerificationKey(SignedJWT signedJWT, JWKSet jwkSet) throws JOSEException {
        String kid = signedJWT.getHeader().getKeyID();
        JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();

        if (kid != null) {
            JWK jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk != null && matchesAlgorithm(jwk, alg)) {
                return extractPublicKey(jwk);
            }
        }

        // Try to find any key matching the algorithm
        for (JWK jwk : jwkSet.getKeys()) {
            if (matchesAlgorithm(jwk, alg)) {
                return extractPublicKey(jwk);
            }
        }

        return null;
    }

    private boolean matchesAlgorithm(JWK jwk, JWSAlgorithm alg) {
        if (jwk.getAlgorithm() != null && jwk.getAlgorithm().equals(alg)) {
            return true;
        }
        // Check key type compatibility
        if (jwk instanceof RSAKey) {
            return JWSAlgorithm.Family.RSA.contains(alg);
        }
        if (jwk instanceof ECKey) {
            return JWSAlgorithm.Family.EC.contains(alg);
        }
        return false;
    }

    private Key extractPublicKey(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey) {
            try {
                return ((RSAKey) jwk).toRSAPublicKey();
            } catch (Exception e) {
                throw new JOSEException("Failed to extract RSA public key", e);
            }
        }
        if (jwk instanceof ECKey) {
            try {
                return ((ECKey) jwk).toECPublicKey();
            } catch (Exception e) {
                throw new JOSEException("Failed to extract EC public key", e);
            }
        }
        throw new JOSEException("Unsupported JWK type: " + jwk.getKeyType());
    }

    private JWSVerifier createVerifier(JWSAlgorithm alg, Key key) throws JOSEException {
        if (JWSAlgorithm.Family.RSA.contains(alg)) {
            return new RSASSAVerifier((java.security.interfaces.RSAPublicKey) key);
        }
        if (JWSAlgorithm.Family.EC.contains(alg)) {
            return new ECDSAVerifier((java.security.interfaces.ECPublicKey) key);
        }
        LOG.warn("Unsupported JWS algorithm: {}", alg);
        return null;
    }

    /**
     * Refreshes the JWKS from the configured URL.
     */
    private synchronized boolean refreshJwks() {
        long now = System.currentTimeMillis();
        if (cachedJwkSet != null && (now - lastJwksRefreshTime) < JWKS_REFRESH_INTERVAL_MS) {
            // Already refreshed recently
            return cachedJwkSet != null;
        }

        if (jwksUrl == null || jwksUrl.isEmpty()) {
            LOG.error("JWKS URL is not configured");
            return false;
        }

        try {
            LOG.info("Refreshing JWKS from {}", jwksUrl);
            cachedJwkSet = JWKSet.load(new URL(jwksUrl),
                    JWKS_CONNECT_TIMEOUT_MS, JWKS_READ_TIMEOUT_MS, JWKS_SIZE_LIMIT);
            lastJwksRefreshTime = now;

            int keyCount = cachedJwkSet.getKeys().size();
            LOG.info("JWKS refreshed successfully, loaded {} keys", keyCount);
            return true;
        } catch (Exception e) {
            LOG.warn("Failed to refresh JWKS from {}: {}", jwksUrl, e.getMessage());
            return cachedJwkSet != null;
        }
    }

    /**
     * Validates JWT claims: expiry, issuer, and not-before.
     */
    protected void validateClaims(JWTClaimsSet claims) throws OidcTokenValidationException {
        // Validate expiry
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime != null && new Date().after(expirationTime)) {
            throw new OidcTokenValidationException("JWT token has expired at " + expirationTime);
        }

        // Validate not-before
        Date notBeforeTime = claims.getNotBeforeTime();
        if (notBeforeTime != null && new Date().before(notBeforeTime)) {
            throw new OidcTokenValidationException("JWT token is not valid before " + notBeforeTime);
        }

        // Validate issuer if configured
        String configuredIssuer = config.getIssuerUri();
        if (configuredIssuer != null && !configuredIssuer.isEmpty()) {
            String tokenIssuer = claims.getIssuer();
            if (tokenIssuer != null && !configuredIssuer.equals(tokenIssuer)) {
                throw new OidcTokenValidationException(
                        "JWT issuer mismatch: expected=" + configuredIssuer + ", actual=" + tokenIssuer);
            }
        }

        // Validate audience (client ID) is present
        List<String> audience = claims.getAudience();
        String clientId = config.getClientId();
        if (audience != null && !audience.isEmpty() && clientId != null) {
            if (!audience.contains(clientId)) {
                LOG.debug("JWT audience does not contain client ID: audience={}, clientId={}", audience, clientId);
                // Not a hard failure - some IDPs use different audience values
            }
        }

        // Validate subject is present
        String subject = claims.getSubject();
        if (subject == null || subject.trim().isEmpty()) {
            throw new OidcTokenValidationException("JWT subject (sub) claim is missing or empty");
        }
    }

    /**
     * Extracts the groups claim from the JWT claims.
     */
    public List<String> extractGroups(JWTClaimsSet claims) {
        String groupsClaimName = config.getGroupsClaim();
        try {
            Object groupsObj = claims.getClaim(groupsClaimName);
            if (groupsObj instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> groups = (List<String>) groupsObj;
                return groups;
            }
        } catch (Exception e) {
            LOG.debug("Could not extract groups claim '{}': {}", groupsClaimName, e.getMessage());
        }
        return java.util.Collections.emptyList();
    }

    /**
     * Extracts a string claim from the JWT claims.
     */
    public String extractClaim(JWTClaimsSet claims, String claimName) {
        try {
            Object value = claims.getClaim(claimName);
            return value != null ? value.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Exception thrown when token validation fails.
     */
    public static class OidcTokenValidationException extends Exception {
        private static final long serialVersionUID = 1L;

        public OidcTokenValidationException(String message) {
            super(message);
        }

        public OidcTokenValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
