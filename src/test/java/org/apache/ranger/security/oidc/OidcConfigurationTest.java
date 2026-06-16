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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class OidcConfigurationTest {

    @Before
    public void setUp() {
        // Clear any system properties from previous tests
        System.clearProperty(OidcConfiguration.OIDC_ENABLED);
        System.clearProperty(OidcConfiguration.OIDC_ISSUER_URI);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_ID);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_SECRET);
        System.clearProperty(OidcConfiguration.OIDC_JWKS_URI);
        System.clearProperty(OidcConfiguration.OIDC_REDIRECT_URI);
        System.clearProperty(OidcConfiguration.OIDC_SCOPE);
        System.clearProperty(OidcConfiguration.OIDC_GROUPS_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_ADMIN_GROUPS);
        System.clearProperty(OidcConfiguration.OIDC_AUTO_CREATE_USER);
        System.clearProperty(OidcConfiguration.OIDC_COOKIE_NAME);
        System.clearProperty(OidcConfiguration.OIDC_TOKEN_HEADER);
        System.clearProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_TOKEN_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_USERINFO_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_END_SESSION_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_EMAIL_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_USERNAME_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_BROWSER_USER_AGENTS);
    }

    @After
    public void tearDown() {
        System.clearProperty(OidcConfiguration.OIDC_ENABLED);
        System.clearProperty(OidcConfiguration.OIDC_ISSUER_URI);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_ID);
        System.clearProperty(OidcConfiguration.OIDC_CLIENT_SECRET);
        System.clearProperty(OidcConfiguration.OIDC_JWKS_URI);
        System.clearProperty(OidcConfiguration.OIDC_REDIRECT_URI);
        System.clearProperty(OidcConfiguration.OIDC_SCOPE);
        System.clearProperty(OidcConfiguration.OIDC_GROUPS_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_ADMIN_GROUPS);
        System.clearProperty(OidcConfiguration.OIDC_AUTO_CREATE_USER);
        System.clearProperty(OidcConfiguration.OIDC_COOKIE_NAME);
        System.clearProperty(OidcConfiguration.OIDC_TOKEN_HEADER);
        System.clearProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_TOKEN_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_USERINFO_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_END_SESSION_ENDPOINT);
        System.clearProperty(OidcConfiguration.OIDC_EMAIL_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_USERNAME_CLAIM);
        System.clearProperty(OidcConfiguration.OIDC_BROWSER_USER_AGENTS);
    }

    @Test
    public void testDefaultsWhenDisabled() {
        OidcConfiguration config = new OidcConfiguration();
        assertFalse("OIDC should be disabled by default", config.isEnabled());
    }

    @Test
    public void testEnabledWithMinimalConfig() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test-client");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret123");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();

        assertTrue("OIDC should be enabled", config.isEnabled());
        assertEquals("https://idp.example.com", config.getIssuerUri());
        assertEquals("test-client", config.getClientId());
        assertEquals("secret123", config.getClientSecret());
        assertEquals("https://idp.example.com/jwks", config.getJwksUri());
        assertEquals("https://ranger.example.com/callback", config.getRedirectUri());
    }

    @Test
    public void testDefaultValues() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test-client");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();

        assertEquals("Default scope mismatch", OidcConfiguration.DEFAULT_SCOPE, config.getScope());
        assertEquals("Default groups claim mismatch", OidcConfiguration.DEFAULT_GROUPS_CLAIM, config.getGroupsClaim());
        assertEquals("Default cookie name mismatch", OidcConfiguration.DEFAULT_COOKIE_NAME, config.getCookieName());
        assertEquals("Default token header mismatch", OidcConfiguration.DEFAULT_TOKEN_HEADER, config.getTokenHeader());
        assertEquals("Default email claim mismatch", OidcConfiguration.DEFAULT_EMAIL_CLAIM, config.getEmailClaim());
        assertEquals("Default username claim mismatch", OidcConfiguration.DEFAULT_USERNAME_CLAIM, config.getUsernameClaim());
        assertTrue("Auto-create user should default to true", config.isAutoCreateUser());
    }

    @Test
    public void testCustomValuesOverrideDefaults() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "my-client");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "my-secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");
        System.setProperty(OidcConfiguration.OIDC_SCOPE, "openid email");
        System.setProperty(OidcConfiguration.OIDC_GROUPS_CLAIM, "roles");
        System.setProperty(OidcConfiguration.OIDC_COOKIE_NAME, "custom_oidc_cookie");
        System.setProperty(OidcConfiguration.OIDC_TOKEN_HEADER, "X-Auth-Token");
        System.setProperty(OidcConfiguration.OIDC_EMAIL_CLAIM, "mail");
        System.setProperty(OidcConfiguration.OIDC_USERNAME_CLAIM, "sub");
        System.setProperty(OidcConfiguration.OIDC_AUTO_CREATE_USER, "false");

        OidcConfiguration config = new OidcConfiguration();

        assertEquals("openid email", config.getScope());
        assertEquals("roles", config.getGroupsClaim());
        assertEquals("custom_oidc_cookie", config.getCookieName());
        assertEquals("X-Auth-Token", config.getTokenHeader());
        assertEquals("mail", config.getEmailClaim());
        assertEquals("sub", config.getUsernameClaim());
        assertFalse("Auto-create user should be false", config.isAutoCreateUser());
    }

    @Test
    public void testAdminGroupsParsing() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");
        System.setProperty(OidcConfiguration.OIDC_ADMIN_GROUPS, "ranger-admins,ops-team,security-leads");

        OidcConfiguration config = new OidcConfiguration();

        List<String> adminGroups = config.getAdminGroups();
        assertNotNull(adminGroups);
        assertEquals(3, adminGroups.size());
        assertTrue(adminGroups.contains("ranger-admins"));
        assertTrue(adminGroups.contains("ops-team"));
        assertTrue(adminGroups.contains("security-leads"));
    }

    @Test
    public void testAdminGroupsEmptyByDefault() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();

        List<String> adminGroups = config.getAdminGroups();
        assertNotNull(adminGroups);
        assertTrue("Admin groups should be empty by default", adminGroups.isEmpty());
    }

    @Test
    public void testBrowserUserAgentsDefault() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();

        String[] agents = config.getBrowserUserAgents();
        assertNotNull(agents);
        assertTrue(agents.length >= 3);
    }

    @Test
    public void testCustomBrowserUserAgents() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");
        System.setProperty(OidcConfiguration.OIDC_BROWSER_USER_AGENTS, "Mozilla,curl");

        OidcConfiguration config = new OidcConfiguration();

        String[] agents = config.getBrowserUserAgents();
        assertNotNull(agents);
        assertEquals(2, agents.length);
        assertEquals("Mozilla", agents[0]);
        assertEquals("curl", agents[1]);
    }

    @Test
    public void testCustomEndpoints() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        System.setProperty(OidcConfiguration.OIDC_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(OidcConfiguration.OIDC_USERINFO_ENDPOINT, "https://idp.example.com/userinfo");
        System.setProperty(OidcConfiguration.OIDC_END_SESSION_ENDPOINT, "https://idp.example.com/logout");

        OidcConfiguration config = new OidcConfiguration();

        assertEquals("https://idp.example.com/auth", config.getAuthEndpoint());
        assertEquals("https://idp.example.com/token", config.getTokenEndpoint());
        assertEquals("https://idp.example.com/userinfo", config.getUserinfoEndpoint());
        assertEquals("https://idp.example.com/logout", config.getEndSessionEndpoint());
    }

    @Test
    public void testReloadConfigurationChangesValues() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp1.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "client1");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret1");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp1.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger1.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();
        assertEquals("https://idp1.example.com", config.getIssuerUri());
        assertEquals("client1", config.getClientId());

        // Change system properties and reload
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp2.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "client2");
        config.loadConfiguration();

        assertEquals("https://idp2.example.com", config.getIssuerUri());
        assertEquals("client2", config.getClientId());
    }

    @Test
    public void testDisableClearsConfig() {
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");

        OidcConfiguration config = new OidcConfiguration();
        assertTrue(config.isEnabled());

        // Disable and reload
        System.setProperty(OidcConfiguration.OIDC_ENABLED, "false");
        config.loadConfiguration();
        assertFalse(config.isEnabled());
    }

    @Test
    public void testPropertyKeyConstants() {
        assertEquals("ranger.oidc.enabled", OidcConfiguration.OIDC_ENABLED);
        assertEquals("ranger.oidc.issuer-uri", OidcConfiguration.OIDC_ISSUER_URI);
        assertEquals("ranger.oidc.client-id", OidcConfiguration.OIDC_CLIENT_ID);
        assertEquals("ranger.oidc.client-secret", OidcConfiguration.OIDC_CLIENT_SECRET);
        assertEquals("ranger.oidc.jwks-uri", OidcConfiguration.OIDC_JWKS_URI);
        assertEquals("ranger.oidc.redirect-uri", OidcConfiguration.OIDC_REDIRECT_URI);
        assertEquals("ranger.oidc.scope", OidcConfiguration.OIDC_SCOPE);
        assertEquals("ranger.oidc.groups-claim", OidcConfiguration.OIDC_GROUPS_CLAIM);
        assertEquals("ranger.oidc.admin-groups", OidcConfiguration.OIDC_ADMIN_GROUPS);
        assertEquals("ranger.oidc.auto-create-user", OidcConfiguration.OIDC_AUTO_CREATE_USER);
        assertEquals("ranger.oidc.cookie-name", OidcConfiguration.OIDC_COOKIE_NAME);
        assertEquals("ranger.oidc.token-header", OidcConfiguration.OIDC_TOKEN_HEADER);
        assertEquals("ranger.oidc.auth-endpoint", OidcConfiguration.OIDC_AUTH_ENDPOINT);
        assertEquals("ranger.oidc.token-endpoint", OidcConfiguration.OIDC_TOKEN_ENDPOINT);
        assertEquals("ranger.oidc.userinfo-endpoint", OidcConfiguration.OIDC_USERINFO_ENDPOINT);
        assertEquals("ranger.oidc.end-session-endpoint", OidcConfiguration.OIDC_END_SESSION_ENDPOINT);
        assertEquals("ranger.oidc.email-claim", OidcConfiguration.OIDC_EMAIL_CLAIM);
        assertEquals("ranger.oidc.username-claim", OidcConfiguration.OIDC_USERNAME_CLAIM);
        assertEquals("ranger.oidc.browser.useragent", OidcConfiguration.OIDC_BROWSER_USER_AGENTS);
    }
}
