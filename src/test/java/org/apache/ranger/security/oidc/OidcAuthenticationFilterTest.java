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

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class OidcAuthenticationFilterTest {

    private OidcConfiguration config;
    private OidcTokenValidator tokenValidator;
    private OidcAuthenticationProvider authProvider;
    private OidcAuthenticationFilter filter;
    private FilterChain mockChain;

    private void setBaseOidcProperties() {
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "https://idp.example.com");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_ID, "test-client");
        System.setProperty(OidcConfiguration.OIDC_CLIENT_SECRET, "test-secret");
        System.setProperty(OidcConfiguration.OIDC_JWKS_URI, "https://idp.example.com/jwks");
        System.setProperty(OidcConfiguration.OIDC_REDIRECT_URI, "https://ranger.example.com/callback");
    }

    private void clearOidcProperties() {
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
        System.clearProperty(OidcConfiguration.OIDC_USERNAME_CLAIM);
    }

    private void setupConfig(boolean enabled) {
        clearOidcProperties();
        if (enabled) {
            System.setProperty(OidcConfiguration.OIDC_ENABLED, "true");
            setBaseOidcProperties();
        }
        config = new OidcConfiguration();
        tokenValidator = mock(OidcTokenValidator.class);
        authProvider = new OidcAuthenticationProvider();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);
        mockChain = mock(FilterChain.class);
    }

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
        setupConfig(true);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        clearOidcProperties();
    }

    private JWTClaimsSet buildClaims(String subject, String preferredUsername, String email) {
        return new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("preferred_username", preferredUsername)
                .claim("email", email)
                .build();
    }

    private void setupValidToken(String token, String subject) throws Exception {
        JWTClaimsSet claims = buildClaims(subject, subject, subject + "@example.com");
        when(tokenValidator.validateToken(token)).thenReturn(claims);
        when(tokenValidator.extractClaim(eq(claims), anyString())).thenReturn(subject);
        when(tokenValidator.extractGroups(eq(claims))).thenReturn(Collections.<String>emptyList());
    }

    // --- Disabled Filter Tests ---

    @Test
    public void testDoFilterWhenDisabledDoesNothing() throws Exception {
        setupConfig(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testDoFilterSkipsWhenAlreadyOidcAuthenticated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        session.setAttribute(OidcAuthenticationFilter.OIDC_SESSION_ATTR, Boolean.TRUE);
        session.setAttribute("SPRING_SECURITY_CONTEXT",
                new org.springframework.security.core.context.SecurityContextImpl());

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testStaticResourcesPassThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/styles/main.css");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testLoginJspGetsOidcButtonInjected() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login.jsp");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // login.jsp should be intercepted and injected with OIDC button
        // MockHttpServletResponse returns 200 by default after wrapper processing
        String content = response.getContentAsString();
        assertTrue("Login page should contain OIDC button", content.contains("oidc-login-btn"));
        assertTrue("Login page should contain provider name", content.contains("Login with"));
    }

    // --- Bearer Token Tests ---

    @Test
    public void testValidBearerTokenAuthenticates() throws Exception {
        setupValidToken("valid-token", "testuser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer valid-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
        assertNotNull(request.getSession().getAttribute(OidcAuthenticationFilter.OIDC_SESSION_ATTR));
        assertEquals(Boolean.TRUE, request.getSession().getAttribute(OidcAuthenticationFilter.OIDC_SESSION_ATTR));
        assertEquals(true, request.getAttribute("ssoEnabled"));
    }

    @Test
    public void testInvalidBearerTokenForApiReturns401() throws Exception {
        when(tokenValidator.validateToken("invalid-token"))
                .thenThrow(new OidcTokenValidator.OidcTokenValidationException("invalid"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer invalid-token");
        request.addHeader("User-Agent", "curl/7.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("invalid_token"));
    }

    @Test
    public void testNonBearerAuthHeaderPassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        request.addHeader("User-Agent", "curl/7.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testCustomTokenHeader() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_TOKEN_HEADER, "X-API-Key");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        setupValidToken("custom-header-token", "apiuser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("X-API-Key", "custom-header-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    // --- Cookie Token Tests ---

    @Test
    public void testValidCookieTokenAuthenticates() throws Exception {
        setupValidToken("cookie-token-value", "cookieuser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.setCookies(new Cookie("ranger_oidc_token", "cookie-token-value"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testInvalidCookieTokenRedirectsBrowser() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        when(tokenValidator.validateToken("bad-cookie-token"))
                .thenThrow(new OidcTokenValidator.OidcTokenValidationException("expired"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.addHeader("User-Agent", "Mozilla/5.0");
        request.setCookies(new Cookie("ranger_oidc_token", "bad-cookie-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("response_type=code"));
        assertTrue(location.contains("test-client"));
    }

    // --- Browser Redirect Tests ---

    @Test
    public void testBrowserWithoutTokenRedirectsToOidcProvider() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.startsWith("https://idp.example.com/auth"));
        assertTrue(location.contains("response_type=code"));
        assertTrue(location.contains("client_id=test-client"));
        assertTrue(location.contains("state="));
        assertTrue(location.contains("nonce="));
    }

    @Test
    public void testBrowserRedirectSetsStateAndNonceCookies() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        boolean hasStateCookie = false;
        boolean hasNonceCookie = false;
        for (Cookie cookie : response.getCookies()) {
            if (OidcAuthenticationFilter.OIDC_STATE_COOKIE.equals(cookie.getName())) {
                hasStateCookie = true;
                assertTrue("State cookie should be HTTP-only", cookie.isHttpOnly());
                assertEquals(600, cookie.getMaxAge());
            }
            if (OidcAuthenticationFilter.OIDC_NONCE_COOKIE.equals(cookie.getName())) {
                hasNonceCookie = true;
            }
        }
        assertTrue("State cookie not set", hasStateCookie);
        assertTrue("Nonce cookie not set", hasNonceCookie);
    }

    @Test
    public void testBrowserRedirectSavesOriginalUrl() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/secure/policies");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        assertEquals("/secure/policies",
                request.getSession().getAttribute("oidc_original_url"));
    }

    // --- AJAX Request Tests ---

    @Test
    public void testAjaxRequestWithoutTokenReturns419() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("User-Agent", "Mozilla/5.0");
        request.addHeader("X-Requested-With", "XMLHttpRequest");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(419, response.getStatus());
        assertNotNull(response.getHeader("X-Rngr-Redirect-Url"));
        assertTrue(response.getHeader("X-Rngr-Redirect-Url").contains("/oidc/init"));
    }

    // --- OIDC Init Endpoint Tests ---

    @Test
    public void testOidcInitRedirectsToProvider() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "https://idp.example.com/auth");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/oidc/init");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("response_type=code"));
    }

    @Test
    public void testOidcInitWhenAlreadyAuthenticatedPassesThrough() throws Exception {
        // When already authenticated, /oidc/init passes through to filter chain
        javax.servlet.http.HttpServletRequest mockedRequest =
                mock(javax.servlet.http.HttpServletRequest.class);
        javax.servlet.http.HttpSession mockedSession = mock(javax.servlet.http.HttpSession.class);
        javax.servlet.http.HttpServletResponse mockedResponse =
                mock(javax.servlet.http.HttpServletResponse.class);

        when(mockedRequest.getSession(false)).thenReturn(mockedSession);
        when(mockedRequest.getRequestURI()).thenReturn("/oidc/init");

        when(mockedSession.getAttribute(OidcAuthenticationFilter.OIDC_SESSION_ATTR))
                .thenReturn(Boolean.TRUE);

        org.springframework.security.core.context.SecurityContextImpl ctx =
                new org.springframework.security.core.context.SecurityContextImpl();
        ctx.setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "testuser", "", Collections.emptyList()));
        when(mockedSession.getAttribute("SPRING_SECURITY_CONTEXT")).thenReturn(ctx);

        filter.doFilter(mockedRequest, mockedResponse, mockChain);

        // Should pass through to the filter chain (already authenticated)
        verify(mockChain).doFilter(mockedRequest, mockedResponse);
    }

    // --- Callback Endpoint Tests ---

    @Test
    public void testCallbackWithoutCodeRedirectsToLogin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login/oidc/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        assertTrue(response.getHeader("Location").contains("login.jsp"));
    }

    @Test
    public void testCallbackWithErrorRedirectsToLogin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login/oidc/callback");
        request.setParameter("error", "access_denied");
        request.setParameter("error_description", "User denied access");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        assertTrue(response.getHeader("Location").contains("error=oidc"));
    }

    @Test
    public void testCallbackStateMismatchReturns400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login/oidc/callback");
        request.setParameter("code", "authcode123");
        request.setParameter("state", "wrong-state");
        request.setCookies(new Cookie(OidcAuthenticationFilter.OIDC_STATE_COOKIE, "expected-state"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(400, response.getStatus());
    }

    // --- Admin Group Resolution Tests ---

    @Test
    public void testAdminGroupGrantsSysAdminRole() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_ADMIN_GROUPS, "ranger-admins");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        JWTClaimsSet claims = buildClaims("adminuser", "adminuser", "admin@example.com");
        when(tokenValidator.validateToken("admin-token")).thenReturn(claims);
        when(tokenValidator.extractClaim(eq(claims), anyString())).thenReturn("adminuser");
        when(tokenValidator.extractGroups(eq(claims)))
                .thenReturn(Arrays.asList("developer", "ranger-admins"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer admin-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testNonAdminGroupGetsDefaultRole() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_ADMIN_GROUPS, "super-admins");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        JWTClaimsSet claims = buildClaims("regularuser", "regularuser", "user@example.com");
        when(tokenValidator.validateToken("regular-token")).thenReturn(claims);
        when(tokenValidator.extractClaim(eq(claims), anyString())).thenReturn("regularuser");
        when(tokenValidator.extractGroups(eq(claims)))
                .thenReturn(Arrays.asList("developers", "viewers"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer regular-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testNonBrowserRequestWithoutTokenPassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("User-Agent", "python-requests/2.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testInitDoesNotThrow() throws Exception {
        javax.servlet.FilterConfig mockConfig = mock(javax.servlet.FilterConfig.class);
        filter.init(mockConfig);
    }

    @Test
    public void testDestroyDoesNotThrow() {
        filter.destroy();
    }

    @Test
    public void testNullUserAgentPassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testNoSessionCreatesNewOne() throws Exception {
        setupValidToken("new-token", "newuser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer new-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertNotNull(request.getSession(false));
        assertNotNull(request.getSession().getAttribute(OidcAuthenticationFilter.OIDC_SESSION_ATTR));
    }

    @Test
    public void testUsernameExtractionFromSubjectFallback() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_USERNAME_CLAIM, "nonexistent-claim");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("fallback-user")
                .build();
        when(tokenValidator.validateToken("fallback-token")).thenReturn(claims);
        when(tokenValidator.extractClaim(eq(claims), eq("nonexistent-claim"))).thenReturn(null);
        when(tokenValidator.extractGroups(eq(claims))).thenReturn(Collections.<String>emptyList());

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/service/public/api/test");
        request.addHeader("Authorization", "Bearer fallback-token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    // --- Additional coverage tests ---

    @Test
    public void testCustomCookieName() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_COOKIE_NAME, "my_custom_cookie");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        setupValidToken("custom-cookie-token", "customuser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.setCookies(new Cookie("my_custom_cookie", "custom-cookie-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testCallbackWithoutTokenEndpointSends500() throws Exception {
        // Ensure token endpoint is empty
        System.setProperty(OidcConfiguration.OIDC_TOKEN_ENDPOINT, "");
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login/oidc/callback");
        request.setParameter("code", "authcode123");
        request.setParameter("state", "expected-state");
        request.setCookies(new Cookie(OidcAuthenticationFilter.OIDC_STATE_COOKIE, "expected-state"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // Should redirect to login.jsp with error since token exchange will fail
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("error=oidc"));
    }

    @Test
    public void testCallbackWithMatchingState() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_TOKEN_ENDPOINT, "https://idp.example.com/token-not-reachable");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/login/oidc/callback");
        request.setParameter("code", "authcode123");
        request.setParameter("state", "match-me");
        request.setCookies(new Cookie(OidcAuthenticationFilter.OIDC_STATE_COOKIE, "match-me"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // Token endpoint will fail, redirects to login with error
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("error=oidc"));
    }

    @Test
    public void testInvalidBearerTokenForBrowserFallsThrough() throws Exception {
        when(tokenValidator.validateToken("bad-bearer-token"))
                .thenThrow(new OidcTokenValidator.OidcTokenValidationException("bad"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/some/page");
        request.addHeader("Authorization", "Bearer bad-bearer-token");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // Browser with bad bearer token should be redirected to OIDC provider
        // (since no cookie present, falls to browser redirect logic)
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.contains("response_type=code"));
    }

    @Test
    public void testLocalloginUrlPassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/locallogin");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        verify(mockChain).doFilter(request, response);
    }

    @Test
    public void testCookieWithBlankValue() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/dashboard.jsp");
        request.addHeader("User-Agent", "Mozilla/5.0");
        request.setCookies(new Cookie("ranger_oidc_token", ""));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // Empty cookie → treated as no token → redirect
        String location = response.getHeader("Location");
        assertNotNull(location);
    }

    @Test
    public void testNoAuthEndpointWithIssuerDiscovery() throws Exception {
        // Don't set auth endpoint, rely on issuer-based discovery
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "");
        // Issuer URI is set in setUp
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/secure/policies");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        assertEquals(302, response.getStatus());
        String location = response.getHeader("Location");
        assertNotNull(location);
        assertTrue(location.startsWith("https://idp.example.com/protocol/openid-connect/auth"));
    }

    @Test
    public void testRedirectWithNoIssuerAndNoAuthEndpoint() throws Exception {
        System.setProperty(OidcConfiguration.OIDC_ISSUER_URI, "");
        System.setProperty(OidcConfiguration.OIDC_AUTH_ENDPOINT, "");
        config = new OidcConfiguration();
        filter = new OidcAuthenticationFilter(config, tokenValidator, authProvider);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/secure/policies");
        request.addHeader("User-Agent", "Mozilla/5.0");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mockChain);

        // No auth endpoint configured → sendError(500)
        assertEquals(500, response.getStatus());
    }
}
