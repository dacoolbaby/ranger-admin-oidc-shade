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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;

import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.junit.Assert.*;

public class OidcTokenValidatorTest {

    private RSAKey rsaKey;
    private OidcTokenValidator validator;
    private OidcConfiguration config;
    private String issuer;
    private String clientId;

    @Before
    public void setUp() throws Exception {
        // Generate RSA key pair for signing test JWTs
        rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-kid-1")
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        // Configure OIDC
        issuer = "https://idp.example.com";
        clientId = "test-client";

        // Clear all OIDC properties to ensure test isolation
        System.clearProperty(OidcConfiguration.OIDC_ENABLED);
        System.clearProperty(OidcConfiguration.OIDC_ISSUER_URI);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_ID);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_SECRET);
        System.clearProperty(OidcConfiguration.OIDC_JWKS_URI);
        System.clearProperty(OidcConfiguration.OIDC_REDIRECT_URI);
        System.clearProperty(OidcConfiguration.OIDC_GROUPS_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_ADMIN_GROUPS);

        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, issuer);
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, clientId);
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        config = new OidcConfiguration();
        validator = new OidcTokenValidator(config);
    }

    private String createValidToken(String subject, Date expiration, Map<String, Object> extraClaims) throws Exception {
        JWSSigner signer = new RSASSASigner(rsaKey);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .audience(clientId)
                .issueTime(new Date())
                .expirationTime(expiration);

        if (extraClaims != null) {
            for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
        }

        JWTClaimsSet claims = builder.build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    // --- Validation Tests ---

    @Test
    public void testValidateNullToken() {
        try {
            validator.validateToken(null);
            fail("Should throw exception for null token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("null") || e.getMessage().contains("empty"));
        }
    }

    @Test
    public void testValidateEmptyToken() {
        try {
            validator.validateToken("");
            fail("Should throw exception for empty token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("null") || e.getMessage().contains("empty"));
        }
    }

    @Test
    public void testValidateMalformedToken() {
        try {
            validator.validateToken("not.a.valid.jwt.token.....");
            fail("Should throw exception for malformed token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("Failed to parse"));
        }
    }

    @Test
    public void testValidateTamperedToken() {
        try {
            // Tampered token (random string in JWT format)
            validator.validateToken("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.tampered");
            fail("Should throw exception for tampered token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("Failed to parse") || e.getMessage().contains("signature"));
        }
    }

    @Test
    public void testValidateExpiredToken() throws Exception {
        Date pastDate = new Date(System.currentTimeMillis() - 3600_000); // 1 hour ago
        // We need a token that WAS valid but expired
        // Creating with expired time means signature validation will also fail since
        // the key won't match. But the validator checks expiry after signature.
        // Let's skip the full flow test since we can't mock JWKS easily in unit tests.
        // Instead, test the claim validation directly.

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .expirationTime(pastDate)
                .build();

        try {
            validator.validateClaims(claims);
            fail("Should throw exception for expired token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("expired"));
        }
    }

    @Test
    public void testValidateClaimsIssuerMismatch() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer("https://wrong-issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        try {
            validator.validateClaims(claims);
            fail("Should throw exception for issuer mismatch");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("issuer"));
        }
    }

    @Test
    public void testValidateClaimsNotBefore() throws Exception {
        Date futureDate = new Date(System.currentTimeMillis() + 3600_000);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 7200_000))
                .notBeforeTime(futureDate)
                .build();

        try {
            validator.validateClaims(claims);
            fail("Should throw exception for not-before violation");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("not valid before"));
        }
    }

    @Test
    public void testValidateClaimsMissingSubject() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        try {
            validator.validateClaims(claims);
            fail("Should throw exception for missing subject");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("sub"));
        }
    }

    @Test
    public void testValidateClaimsValid() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .audience(clientId)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        // Should not throw
        validator.validateClaims(claims);
    }

    @Test
    public void testValidateClaimsNoExpirationPasses() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .build();

        // Token without expiration passes (some IDPs omit this)
        validator.validateClaims(claims);
    }

    // --- Claims Extraction Tests ---

    @Test
    public void testExtractGroups() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_GROUPS_CLAIM, "groups");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("groups", Arrays.asList("admin", "user", "viewer"))
                .build();

        List<String> groups = validator.extractGroups(claims);
        assertEquals(3, groups.size());
        assertTrue(groups.contains("admin"));
        assertTrue(groups.contains("user"));
        assertTrue(groups.contains("viewer"));
    }

    @Test
    public void testExtractGroupsWithCustomClaim() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_GROUPS_CLAIM, "roles");
        config = new OidcConfiguration();
        validator = new OidcTokenValidator(config);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("roles", Arrays.asList("member", "owner"))
                .build();

        List<String> groups = validator.extractGroups(claims);
        assertEquals(2, groups.size());
        assertTrue(groups.contains("member"));
        assertTrue(groups.contains("owner"));
    }

    @Test
    public void testExtractGroupsEmptyWhenClaimMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .build();

        List<String> groups = validator.extractGroups(claims);
        assertNotNull(groups);
        assertTrue(groups.isEmpty());
    }

    @Test
    public void testExtractGroupsEmptyWhenNotList() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_GROUPS_CLAIM, "groups");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("groups", "not-a-list")
                .build();

        List<String> groups = validator.extractGroups(claims);
        assertNotNull(groups);
        assertTrue(groups.isEmpty());
    }

    @Test
    public void testExtractClaim() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("email", "test@example.com")
                .claim("preferred_username", "john.doe")
                .build();

        assertEquals("test@example.com", validator.extractClaim(claims, "email"));
        assertEquals("john.doe", validator.extractClaim(claims, "preferred_username"));
        assertNull(validator.extractClaim(claims, "nonexistent"));
    }

    @Test
    public void testExtractClaimNullForNullClaimName() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .build();

        assertNull(validator.extractClaim(claims, null));
    }

    // --- Signature Validation Tests (with JWKS mocking limitation) ---

    @Test
    public void testValidateTokenWithUnknownKeyFails() throws Exception {
        // Create a token signed with a different key that's not in any JWKS
        RSAKey otherKey = new RSAKeyGenerator(2048)
                .keyID("unknown-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        JWSSigner signer = new RSASSASigner(otherKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-kid").build(),
                claims);
        signedJWT.sign(signer);

        try {
            validator.validateToken(signedJWT.serialize());
            fail("Should throw exception for unknown key");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            assertTrue(e.getMessage().contains("signature"));
        }
    }

    // --- OidcTokenValidationException Tests ---

    @Test
    public void testValidationExceptionMessage() {
        OidcTokenValidator.OidcTokenValidationException ex =
                new OidcTokenValidator.OidcTokenValidationException("test message");
        assertEquals("test message", ex.getMessage());
    }

    @Test
    public void testValidationExceptionWithCause() {
        Exception cause = new RuntimeException("root cause");
        OidcTokenValidator.OidcTokenValidationException ex =
                new OidcTokenValidator.OidcTokenValidationException("test message", cause);
        assertEquals("test message", ex.getMessage());
        assertEquals(cause, ex.getCause());
    }

    // --- RS256/ES256 Support Tests ---

    @Test
    public void testValidateSignatureWithRS256SignedToken() throws Exception {
        // Create a signed token with RS256
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("sigtest")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        // Test direct signature verification
        boolean result = validator.validateSignature(signedJWT);
        assertFalse("Should fail when key is not in JWKS (no JWKS endpoint available)", result);
    }

    @Test
    public void testValidateSignatureWithUnsignedToken() throws Exception {
        // Create a JWT in UNSIGNED state using the API
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test")
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT unsignedJWT = new SignedJWT(header, claims);
        // Not signing it - stays in UNSIGNED state

        boolean result = validator.validateSignature(unsignedJWT);
        assertFalse("Unsigned token should fail validation", result);
    }

    // --- Additional coverage tests ---

    @Test
    public void testValidateTokenWithWhitespaceOnly() {
        try {
            validator.validateToken("   ");
            fail("Should throw exception for whitespace token");
        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            // expected
        }
    }

    @Test
    public void testValidateClaimsExpirationNullPasses() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .build(); // No expiration
        validator.validateClaims(claims); // Should not throw
    }

    @Test
    public void testValidateClaimsIssuerNullWhenConfigured() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(null)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        validator.validateClaims(claims); // issuer=null won't mismatch with configured issuer
    }

    // --- JWKS-based signature validation tests (using reflection) ---

    @Test
    public void testValidateSignatureWithMatchingCachedKey() throws Exception {
        // Create a JWKSet with our test key and inject it via reflection
        com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK());

        java.lang.reflect.Field cachedField = OidcTokenValidator.class.getDeclaredField("cachedJwkSet");
        cachedField.setAccessible(true);
        cachedField.set(validator, jwkSet);

        java.lang.reflect.Field refreshField = OidcTokenValidator.class.getDeclaredField("lastJwksRefreshTime");
        refreshField.setAccessible(true);
        refreshField.set(validator, System.currentTimeMillis());

        // Sign a token with the same key that's in the JWK set
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("jwks-test-user")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        boolean result = validator.validateSignature(signedJWT);
        assertTrue("Signature should validate successfully with matching cached key", result);
    }

    @Test
    public void testValidateTokenWithMatchingCachedKey() throws Exception {
        // Full token validation with cached JWK set
        com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK());

        java.lang.reflect.Field cachedField = OidcTokenValidator.class.getDeclaredField("cachedJwkSet");
        cachedField.setAccessible(true);
        cachedField.set(validator, jwkSet);

        java.lang.reflect.Field refreshField = OidcTokenValidator.class.getDeclaredField("lastJwksRefreshTime");
        refreshField.setAccessible(true);
        refreshField.set(validator, System.currentTimeMillis());

        // Create and sign a valid token
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("full-validation-test")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .claim("preferred_username", "fulltest")
                .claim("groups", Arrays.asList("dev", "test"))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        JWTClaimsSet validated = validator.validateToken(signedJWT.serialize());
        assertEquals("full-validation-test", validated.getSubject());
        assertTrue(validator.extractGroups(validated).contains("dev"));
    }

    @Test
    public void testValidateSignatureWithNonMatchingKey() throws Exception {
        // JWK set has a different key than the one used to sign
        RSAKey differentKey = new RSAKeyGenerator(2048)
                .keyID("different-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(differentKey.toPublicJWK());

        java.lang.reflect.Field cachedField = OidcTokenValidator.class.getDeclaredField("cachedJwkSet");
        cachedField.setAccessible(true);
        cachedField.set(validator, jwkSet);

        java.lang.reflect.Field refreshField = OidcTokenValidator.class.getDeclaredField("lastJwksRefreshTime");
        refreshField.setAccessible(true);
        refreshField.set(validator, System.currentTimeMillis());

        // Sign with our original key (not in JWK set)
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        signedJWT.sign(signer);

        boolean result = validator.validateSignature(signedJWT);
        assertFalse("Should fail when key is not in JWK set", result);
    }

    @Test
    public void testValidateSignatureWithCachedKeyNoKid() throws Exception {
        // JWK set with matching key but token has no kid
        com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK());

        java.lang.reflect.Field cachedField = OidcTokenValidator.class.getDeclaredField("cachedJwkSet");
        cachedField.setAccessible(true);
        cachedField.set(validator, jwkSet);

        java.lang.reflect.Field refreshField = OidcTokenValidator.class.getDeclaredField("lastJwksRefreshTime");
        refreshField.setAccessible(true);
        refreshField.set(validator, System.currentTimeMillis());

        // Sign without key ID in header
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(), // no key ID
                claims);
        signedJWT.sign(signer);

        boolean result = validator.validateSignature(signedJWT);
        assertTrue("Should validate without kid by algorithm matching", result);
    }

    @Test
    public void testExtractGroupsNonListClaim() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("groups", "single-string-value")
                .build();
        List<String> groups = validator.extractGroups(claims);
        assertTrue(groups.isEmpty());
    }

    @Test
    public void testExtractClaimWithBooleanValue() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("email_verified", true)
                .build();
        assertEquals("true", validator.extractClaim(claims, "email_verified"));
    }

    @Test
    public void testExtractClaimWithNumberValue() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .claim("updated_at", 1234567890L)
                .build();
        assertEquals("1234567890", validator.extractClaim(claims, "updated_at"));
    }

    @Test
    public void testValidateClaimsWithAudienceMatching() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .audience(clientId)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        // When audience matches clientId, no exception
        validator.validateClaims(claims);
    }

    @Test
    public void testValidateSignatureWithNullKeyId() throws Exception {
        // Create signed token without key ID
        JWSSigner signer = new RSASSASigner(rsaKey);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("sigtest")
                .issuer(issuer)
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).build(), // no key ID
                claims);
        signedJWT.sign(signer);

        boolean result = validator.validateSignature(signedJWT);
        assertFalse("Should fail without JWKS endpoint configured", result);
    }

    @Test
    public void testConstructorConfiguresJwksUrl() {
        assertEquals("https://idp.example.com/jwks", config.getJwksUri());
        assertNotNull(validator); // Verify construction succeeds
    }

    @Test
    public void testValidateClaimsWithEmptyAudience() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("testuser")
                .issuer(issuer)
                .audience(new ArrayList<String>())
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();
        validator.validateClaims(claims); // Empty audience - no client ID check
    }
}
