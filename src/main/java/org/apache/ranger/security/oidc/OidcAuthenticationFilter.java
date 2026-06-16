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
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

/**
 * OIDC Authentication Filter for Apache Ranger Admin.
 *
 * This filter is registered as a Servlet filter before the Spring Security
 * DelegatingFilterProxy. It intercepts requests and checks for OIDC Bearer
 * tokens (in Authorization header) or OIDC session cookies.
 *
 * On successful authentication, the SecurityContext is stored in the
 * HTTP session using the Spring Security session key, so Spring Security's
 * SecurityContextPersistenceFilter picks it up automatically.
 *
 * This follows the same pattern as {@code RangerSSOAuthenticationFilter}
 * but for OIDC/OAuth2 identity providers (Keycloak, Okta, Azure AD, etc.).
 *
 * <h3>Ranger Integration</h3>
 * The filter sets {@code request.setAttribute("ssoEnabled", true)} so that
 * Ranger's {@code RangerSecurityContextFormationFilter} uses
 * {@code AUTH_TYPE_SSO} (value 3) for audit trail and triggers
 * auto-provisioning in {@code SessionMgr.getSSOSpnegoAuthCheckForAPI()}.
 */
public class OidcAuthenticationFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationFilter.class);

    public static final String OIDC_SESSION_ATTR = "oidc_authenticated";
    public static final String OIDC_STATE_ATTR = "oidc_state";
    public static final String OIDC_NONCE_ATTR = "oidc_nonce";

    /** HTTP status code used by Ranger for authentication timeout (419). */
    private static final int SC_AUTHENTICATION_TIMEOUT = 419;

    /** Default role for new OIDC users. */
    private static final String DEFAULT_ROLE = "ROLE_USER";

    private static final String SPRING_SECURITY_CONTEXT_KEY =
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

    private final OidcConfiguration config;
    private final OidcTokenValidator tokenValidator;

    /**
     * Callback to check if an OIDC-authenticated user exists in the Ranger database.
     * Return true if the user may proceed, false if the user does not exist and should be denied.
     * Set via {@link #setUserExistenceChecker(UserExistenceChecker)}.
     */
    public interface UserExistenceChecker {
        /** Returns true if the user exists in Ranger. */
        boolean userExists(String loginId);
    }

    private UserExistenceChecker userExistenceChecker;

    public OidcAuthenticationFilter(OidcConfiguration config,
                                     OidcTokenValidator tokenValidator,
                                     OidcAuthenticationProvider authenticationProvider) {
        this.config = config;
        this.tokenValidator = tokenValidator;
    }

    public void setUserExistenceChecker(UserExistenceChecker userExistenceChecker) {
        this.userExistenceChecker = userExistenceChecker;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        if (!config.isEnabled()) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        String requestURI = httpRequest.getRequestURI();

        // Already authenticated via OIDC (session attribute check)
        if (isAlreadyOidcAuthenticated(httpRequest)) {
            LOG.debug("Request already OIDC-authenticated");
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        // Handle OIDC callback (authorization code flow response)
        if (requestURI.contains("/login/oidc/callback")) {
            handleOidcCallback(httpRequest, httpResponse, filterChain);
            return;
        }

        // Handle OIDC initiation endpoint
        if (requestURI.contains("/oidc/init")) {
            handleOidcInit(httpRequest, httpResponse);
            return;
        }

        // Inject OIDC login button into login.jsp response
        if (isOnLoginPage(requestURI) && isWebUserAgent(httpRequest.getHeader("User-Agent"))) {
            injectOidcLoginButton(httpRequest, httpResponse, filterChain);
            return;
        }

        // Try Bearer token in Authorization header (for API clients)
        String bearerToken = extractBearerToken(httpRequest);
        if (bearerToken != null) {
            AuthResult result = authenticateWithToken(httpRequest, httpResponse, bearerToken);
            if (result == AuthResult.SUCCESS) {
                filterChain.doFilter(servletRequest, servletResponse);
                return;
            }
            if (result == AuthResult.USER_NOT_FOUND) {
                return; // error response already written
            }
            // Invalid token for API request
            if (!isWebUserAgent(httpRequest.getHeader("User-Agent"))) {
                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write("{\"error\":\"invalid_token\"}");
                return;
            }
        }

        // Try OIDC session cookie (for browser sessions)
        String cookieToken = getTokenFromCookie(httpRequest);
        if (cookieToken != null) {
            AuthResult result = authenticateWithToken(httpRequest, httpResponse, cookieToken);
            if (result == AuthResult.SUCCESS) {
                filterChain.doFilter(servletRequest, servletResponse);
                return;
            }
            if (result == AuthResult.USER_NOT_FOUND) {
                return; // error response already written
            }
        }

        // No valid token: redirect browser to OIDC provider
        // (also redirect if a cookie or Bearer token was present but invalid)
        if (isWebUserAgent(httpRequest.getHeader("User-Agent"))) {
            String ajaxHeader = httpRequest.getHeader("X-Requested-With");
            if ("XMLHttpRequest".equals(ajaxHeader)) {
                httpResponse.setHeader("X-Frame-Options", "DENY");
                httpResponse.setStatus(SC_AUTHENTICATION_TIMEOUT);
                httpResponse.setHeader("X-Rngr-Redirect-Url",
                        httpRequest.getContextPath() + "/oidc/init");
            } else if (!isStaticResource(requestURI)) {
                redirectToOidcProvider(httpRequest, httpResponse);
                return;
            }
        }

        // Continue to Spring Security chain (form login, etc.)
        filterChain.doFilter(servletRequest, servletResponse);
    }

    // --- Login Page Injection ---

    private boolean isOnLoginPage(String uri) {
        return uri != null && (uri.endsWith("/login.jsp") || uri.endsWith("/login.jsp/")
                || uri.equals("/login.jsp") || uri.contains("/login.jsp?"));
    }

    /**
     * Wraps the login.jsp response to inject a "Login with {Provider}" button.
     * Uses a simple {@link javax.servlet.http.HttpServletResponseWrapper} that
     * captures the HTML output and appends the button before &lt;/body&gt;.
     */
    private void injectOidcLoginButton(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain chain) throws IOException, ServletException {
        CharResponseWrapper wrapper = new CharResponseWrapper(response);
        chain.doFilter(request, wrapper);

        String originalContent = wrapper.toString();
        String injectedContent = injectLoginButtonHtml(originalContent, request.getContextPath());

        response.setContentType("text/html");
        byte[] contentBytes = injectedContent.getBytes(response.getCharacterEncoding());
        response.setContentLength(contentBytes.length);
        response.getWriter().write(injectedContent);
    }

    private String injectLoginButtonHtml(String html, String contextPath) {
        String providerName = config.getProviderName();
        String oidcInitUrl = contextPath + "/oidc/init";

        StringBuilder buttonHtml = new StringBuilder();
        buttonHtml.append("\n<!-- OIDC Login injected by ranger-admin-oidc-shade -->\n");
        buttonHtml.append("<style>\n");
        buttonHtml.append(".oidc-login-section { text-align:center; margin-top:20px; padding:15px; ")
                .append("border-top:1px solid #ddd; }\n");
        buttonHtml.append(".oidc-login-btn { display:inline-block; padding:10px 30px; ")
                .append("background-color:#0078D4; color:white; text-decoration:none; ")
                .append("border-radius:4px; font-family:Arial,sans-serif; font-size:14px; }\n");
        buttonHtml.append(".oidc-login-btn:hover { background-color:#106EBE; }\n");
        buttonHtml.append(".oidc-login-separator { display:flex; align-items:center; margin:20px 0; ")
                .append("color:#888; font-size:12px; }\n");
        buttonHtml.append(".oidc-login-separator::before,.oidc-login-separator::after ")
                .append("{ content:''; flex:1; border-bottom:1px solid #ddd; }\n");
        buttonHtml.append(".oidc-login-separator span { padding:0 10px; }\n");
        buttonHtml.append("</style>\n");
        buttonHtml.append("<div class=\"oidc-login-section\">\n");
        buttonHtml.append("  <div class=\"oidc-login-separator\"><span>or</span></div>\n");
        buttonHtml.append("  <a href=\"").append(oidcInitUrl).append("\" class=\"oidc-login-btn\">")
                .append("Login with ").append(escapeHtml(providerName)).append("</a>\n");
        buttonHtml.append("</div>\n");

        // Inject before </body> or append at end
        int bodyCloseIdx = html.lastIndexOf("</body>");
        if (bodyCloseIdx >= 0) {
            return html.substring(0, bodyCloseIdx) + buttonHtml.toString() + html.substring(bodyCloseIdx);
        }
        return html + buttonHtml.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /**
     * Response wrapper that captures the output as a String.
     */
    private static class CharResponseWrapper extends javax.servlet.http.HttpServletResponseWrapper {
        private final java.io.CharArrayWriter charWriter = new java.io.CharArrayWriter();
        private final java.io.PrintWriter printWriter = new java.io.PrintWriter(charWriter);
        private javax.servlet.ServletOutputStream outputStream;

        public CharResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public java.io.PrintWriter getWriter() throws IOException {
            return printWriter;
        }

        @Override
        public javax.servlet.ServletOutputStream getOutputStream() throws IOException {
            if (outputStream == null) {
                outputStream = new javax.servlet.ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        charWriter.write(b);
                    }

                    @Override
                    public boolean isReady() { return true; }

                    @Override
                    public void setWriteListener(javax.servlet.WriteListener listener) {}
                };
            }
            return outputStream;
        }

        @Override
        public String toString() {
            printWriter.flush();
            return charWriter.toString();
        }
    }

    // --- Authentication Logic ---

    /**
     * Result of an authentication attempt.
     */
    private enum AuthResult {
        SUCCESS,
        INVALID_TOKEN,
        USER_NOT_FOUND
    }

    private AuthResult authenticateWithToken(HttpServletRequest httpRequest,
                                              HttpServletResponse httpResponse,
                                              String token) {
        try {
            JWTClaimsSet claims = tokenValidator.validateToken(token);

            String username = extractUsername(claims);
            List<String> groups = tokenValidator.extractGroups(claims);

            // Check if user exists in Ranger DB. If auto-create is disabled and user
            // doesn't exist, deny access with a friendly 403 error page.
            if (userExistenceChecker != null && !config.isAutoCreateUser()) {
                if (!userExistenceChecker.userExists(username)) {
                    LOG.warn("OIDC user '{}' authenticated but not registered in Ranger", username);
                    try {
                        writeUserNotFoundError(httpRequest, httpResponse, username);
                    } catch (IOException e) {
                        LOG.error("Failed to write user-not-found error page", e);
                    }
                    return AuthResult.USER_NOT_FOUND;
                }
            }

            // Build authorities (admin group check + default role)
            List<GrantedAuthority> authorities = resolveAuthorities(username, groups);

            UserDetails principal = new User(username, "", authorities);
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(principal, "", authorities);

            WebAuthenticationDetails webDetails = new WebAuthenticationDetails(httpRequest);
            authToken.setDetails(webDetails);

            // Store in HTTP session so Spring Security picks it up
            SecurityContext securityContext = new SecurityContextImpl();
            securityContext.setAuthentication(authToken);

            HttpSession session = httpRequest.getSession(true);
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, securityContext);
            session.setAttribute(OIDC_SESSION_ATTR, Boolean.TRUE);

            // Set for current thread
            SecurityContextHolder.getContext().setAuthentication(authToken);

            // Signal Ranger's SecurityContextFormationFilter to use AUTH_TYPE_SSO (audit trail).
            // Also set spnegoEnabled to trigger user auto-creation in SessionMgr.getSSOSpnegoAuthCheckForAPI().
            httpRequest.setAttribute("ssoEnabled", true);
            httpRequest.setAttribute("spnegoEnabled", true);

            LOG.info("OIDC authentication successful: username={}, groups={}", username, groups);
            return AuthResult.SUCCESS;

        } catch (OidcTokenValidator.OidcTokenValidationException e) {
            LOG.warn("OIDC token validation failed: {}", e.getMessage());
            return AuthResult.INVALID_TOKEN;
        }
    }

    private void writeUserNotFoundError(HttpServletRequest request,
                                         HttpServletResponse response,
                                         String username) throws IOException {
        if (!isWebUserAgent(request.getHeader("User-Agent"))) {
            // API client: return JSON error
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"user_not_registered\","
                    + "\"message\":\"OIDC user '" + escapeJson(username) + "' is not registered in Ranger.\","
                    + "\"action\":\"Please contact your Ranger administrator to add this user.\"}");
        } else {
            // Browser: return friendly HTML page
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(buildUserNotFoundPage(request.getContextPath(), username));
        }
    }

    private String buildUserNotFoundPage(String contextPath, String username) {
        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "<head>\n"
                + "<meta charset=\"UTF-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
                + "<title>Access Denied - Ranger Admin</title>\n"
                + "<style>\n"
                + "  * { margin:0; padding:0; box-sizing:border-box; }\n"
                + "  body { font-family:Arial,Helvetica,sans-serif; background:#f5f5f5; "
                +          "display:flex; justify-content:center; align-items:center; "
                +          "min-height:100vh; color:#333; }\n"
                + "  .card { background:#fff; border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,0.1); "
                +          "max-width:520px; width:90%; padding:40px; text-align:center; }\n"
                + "  .icon { width:64px; height:64px; background:#d32f2f; border-radius:50%; "
                +          "display:inline-flex; align-items:center; justify-content:center; "
                +          "margin-bottom:20px; }\n"
                + "  .icon span { color:#fff; font-size:32px; font-weight:bold; line-height:1; }\n"
                + "  h1 { font-size:22px; margin-bottom:12px; color:#d32f2f; }\n"
                + "  p { font-size:14px; color:#666; margin-bottom:8px; line-height:1.6; }\n"
                + "  .user { font-family:monospace; background:#fff3e0; padding:2px 8px; "
                +          "border-radius:3px; color:#e65100; font-size:13px; }\n"
                + "  .actions { margin-top:24px; }\n"
                + "  .btn { display:inline-block; padding:10px 24px; border-radius:4px; "
                +         "text-decoration:none; font-size:14px; margin:4px; }\n"
                + "  .btn-primary { background:#1976d2; color:#fff; }\n"
                + "  .btn-primary:hover { background:#1565c0; }\n"
                + "  .btn-secondary { background:#e0e0e0; color:#333; }\n"
                + "  .btn-secondary:hover { background:#d0d0d0; }\n"
                + "</style>\n"
                + "</head>\n"
                + "<body>\n"
                + "<div class=\"card\">\n"
                + "  <div class=\"icon\"><span>&#10005;</span></div>\n"
                + "  <h1>Access Denied</h1>\n"
                + "  <p>Your account <span class=\"user\">" + escapeHtml(username) + "</span> "
                +      "has been authenticated by the OIDC provider,</p>\n"
                + "  <p>but it is <strong>not registered</strong> in Apache Ranger.</p>\n"
                + "  <p style=\"margin-top:16px;\">"
                +      "Please contact your Ranger administrator to add this user,</p>\n"
                + "  <p>or use a different account that has been granted access.</p>\n"
                + "  <div class=\"actions\">\n"
                + "    <a href=\"" + contextPath + "/login.jsp\" "
                +        "class=\"btn btn-primary\">Back to Login</a>\n"
                + "    <a href=\"" + contextPath + "/oidc/init\" "
                +        "class=\"btn btn-secondary\">Try Another Account</a>\n"
                + "  </div>\n"
                + "</div>\n"
                + "</body>\n"
                + "</html>";
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String extractUsername(JWTClaimsSet claims) {
        String username = tokenValidator.extractClaim(claims, config.getUsernameClaim());
        if (StringUtils.isNotBlank(username)) {
            return username;
        }
        return claims.getSubject();
    }

    private List<GrantedAuthority> resolveAuthorities(String username, List<String> oidcGroups) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // Check admin groups from configuration
        List<String> adminGroups = config.getAdminGroups();
        if (!adminGroups.isEmpty() && oidcGroups != null) {
            for (String group : oidcGroups) {
                if (adminGroups.contains(group)) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_SYS_ADMIN"));
                    return authorities;
                }
            }
        }

        // Default role
        authorities.add(new SimpleGrantedAuthority(DEFAULT_ROLE));
        return authorities;
    }

    private boolean isAlreadyOidcAuthenticated(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }
        if (session.getAttribute(OIDC_SESSION_ATTR) == null) {
            return false;
        }
        SecurityContext securityContext =
                (SecurityContext) session.getAttribute(SPRING_SECURITY_CONTEXT_KEY);
        if (securityContext == null) {
            return false;
        }
        Authentication auth = securityContext.getAuthentication();
        return auth != null && auth.isAuthenticated();
    }

    // --- Token Extraction ---

    private String extractBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader(config.getTokenHeader());
        if (StringUtils.isBlank(authHeader)) {
            return null;
        }
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }
        if ("Authorization".equals(config.getTokenHeader())) {
            return null; // Not Bearer format
        }
        return authHeader.trim();
    }

    private String getTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String cookieName = config.getCookieName();
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                String value = cookie.getValue();
                if (StringUtils.isNotBlank(value)) {
                    return value;
                }
            }
        }
        return null;
    }

    // --- User Agent Detection ---

    private boolean isWebUserAgent(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        String[] browsers = config.getBrowserUserAgents();
        if (browsers == null) {
            return false;
        }
        for (String ua : browsers) {
            if (userAgent.startsWith(ua.trim())) {
                return true;
            }
        }
        return false;
    }

    private boolean isStaticResource(String uri) {
        if (uri == null) {
            return false;
        }
        return uri.endsWith(".css") || uri.endsWith(".js") || uri.endsWith(".png")
                || uri.endsWith(".jpg") || uri.endsWith(".gif") || uri.endsWith(".ico")
                || uri.endsWith(".woff") || uri.endsWith(".woff2") || uri.endsWith(".ttf")
                || uri.endsWith(".svg") || uri.endsWith(".eot")
                || uri.contains("/login.jsp") || uri.contains("/locallogin");
    }

    // --- OIDC Authorization Code Flow ---

    private void redirectToOidcProvider(HttpServletRequest request,
                                         HttpServletResponse response) throws IOException {
        String authEndpoint = config.getAuthEndpoint();
        if (StringUtils.isBlank(authEndpoint)) {
            String issuerUri = config.getIssuerUri();
            if (StringUtils.isNotBlank(issuerUri)) {
                authEndpoint = issuerUri;
                if (!authEndpoint.endsWith("/")) {
                    authEndpoint += "/";
                }
                authEndpoint += "protocol/openid-connect/auth";
            }
        }

        if (StringUtils.isBlank(authEndpoint)) {
            LOG.error("OIDC authorization endpoint not configured");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "OIDC authorization endpoint not configured");
            return;
        }

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        // Store state and nonce in HTTP Session (NOT cookie) for CSRF protection.
        // Storing in session ensures only the same browser session that initiated
        // the auth flow can complete it. Cookies would be sent automatically by
        // the browser on CSRF attacks, defeating the purpose of the state parameter.
        HttpSession session = request.getSession(true);
        session.setAttribute(OIDC_STATE_ATTR, state);
        session.setAttribute(OIDC_NONCE_ATTR, nonce);

        // Save original URL for post-login redirect
        String originalUrl = request.getRequestURI();
        if (request.getQueryString() != null) {
            originalUrl += "?" + request.getQueryString();
        }
        session.setAttribute("oidc_original_url", originalUrl);

        // Build authorization URL
        StringBuilder authUrl = new StringBuilder(authEndpoint);
        authUrl.append("?response_type=code");
        authUrl.append("&client_id=").append(URLEncoder.encode(config.getClientId(), "UTF-8"));
        authUrl.append("&redirect_uri=").append(URLEncoder.encode(config.getRedirectUri(), "UTF-8"));
        authUrl.append("&scope=").append(URLEncoder.encode(config.getScope(), "UTF-8"));
        authUrl.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
        authUrl.append("&nonce=").append(URLEncoder.encode(nonce, "UTF-8"));

        LOG.info("Redirecting to OIDC provider: {}", authEndpoint);

        response.sendRedirect(authUrl.toString());
    }

    private void handleOidcInit(HttpServletRequest request,
                                 HttpServletResponse response) throws IOException {
        if (isAlreadyOidcAuthenticated(request)) {
            response.sendRedirect(request.getContextPath() + "/");
            return;
        }
        redirectToOidcProvider(request, response);
    }

    private void handleOidcCallback(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws IOException, ServletException {
        String code = request.getParameter("code");
        String state = request.getParameter("state");
        String error = request.getParameter("error");

        if (error != null) {
            LOG.warn("OIDC provider returned error: {}, description: {}",
                    error, request.getParameter("error_description"));
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc");
            return;
        }

        if (StringUtils.isBlank(code)) {
            LOG.warn("OIDC callback missing authorization code");
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc");
            return;
        }

        // CSRF protection: validate state parameter against session-stored value.
        // State is stored in HTTP Session (not cookie) to prevent CSRF attacks.
        // An attacker cannot access the victim's session state, so a forged
        // callback request will fail this check.
        HttpSession session = request.getSession(false);
        if (session == null) {
            LOG.warn("OIDC callback has no session");
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc");
            return;
        }

        String expectedState = (String) session.getAttribute(OIDC_STATE_ATTR);
        String expectedNonce = (String) session.getAttribute(OIDC_NONCE_ATTR);

        // Remove state/nonce from session immediately (one-time use)
        session.removeAttribute(OIDC_STATE_ATTR);
        session.removeAttribute(OIDC_NONCE_ATTR);

        if (expectedState == null || !expectedState.equals(state)) {
            LOG.warn("OIDC state mismatch: expected={}, got={}", expectedState, state);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state parameter");
            return;
        }

        // Exchange authorization code for tokens
        try {
            TokenResponse tokenResponse = exchangeCodeForTokens(code);

            if (tokenResponse == null || StringUtils.isBlank(tokenResponse.idToken)) {
                LOG.error("Failed to obtain ID token from OIDC token endpoint");
                response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc_token");
                return;
            }

            // Validate the ID token (includes nonce check implicitly via JWT claims)
            JWTClaimsSet claims = tokenValidator.validateToken(tokenResponse.idToken);

            // Verify nonce in ID token matches the one we sent (replay protection)
            String tokenNonce = tokenValidator.extractClaim(claims, "nonce");
            if (expectedNonce != null && !expectedNonce.equals(tokenNonce)) {
                LOG.warn("OIDC nonce mismatch: expected={}, got={}", expectedNonce, tokenNonce);
                response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc_validation");
                return;
            }

            // Store ID token as session cookie for subsequent requests
            Cookie oidcCookie = new Cookie(config.getCookieName(), tokenResponse.idToken);
            oidcCookie.setHttpOnly(true);
            oidcCookie.setSecure(request.isSecure());
            oidcCookie.setPath("/");
            oidcCookie.setMaxAge(-1); // Session cookie
            response.addCookie(oidcCookie);

            // Authenticate
            AuthResult authResult = authenticateWithToken(request, response, tokenResponse.idToken);
            if (authResult == AuthResult.USER_NOT_FOUND) {
                return; // error response already written
            }
            if (authResult == AuthResult.SUCCESS) {
                // Redirect to original URL or home
                String redirectUrl = request.getContextPath() + "/";
                String originalUrl = (String) session.getAttribute("oidc_original_url");
                if (originalUrl != null) {
                    redirectUrl = originalUrl;
                    session.removeAttribute("oidc_original_url");
                }

                LOG.info("OIDC callback processed, redirecting to: {}", redirectUrl);
                response.sendRedirect(redirectUrl);
            } else {
                response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc_validation");
            }

        } catch (Exception e) {
            LOG.error("Error processing OIDC callback: {}", e.getMessage(), e);
            response.sendRedirect(request.getContextPath() + "/login.jsp?error=oidc_server_error");
        }
    }

    // --- Token Endpoint Exchange ---

    private TokenResponse exchangeCodeForTokens(String code) throws IOException {
        String tokenEndpoint = config.getTokenEndpoint();
        if (StringUtils.isBlank(tokenEndpoint)) {
            String issuerUri = config.getIssuerUri();
            if (StringUtils.isNotBlank(issuerUri)) {
                tokenEndpoint = issuerUri;
                if (!tokenEndpoint.endsWith("/")) {
                    tokenEndpoint += "/";
                }
                tokenEndpoint += "protocol/openid-connect/token";
            }
        }

        if (StringUtils.isBlank(tokenEndpoint)) {
            LOG.error("OIDC token endpoint not configured");
            return null;
        }

        URL url = new URL(tokenEndpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Accept", "application/json");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        String params = "grant_type=authorization_code"
                + "&code=" + URLEncoder.encode(code, "UTF-8")
                + "&client_id=" + URLEncoder.encode(config.getClientId(), "UTF-8")
                + "&client_secret=" + URLEncoder.encode(config.getClientSecret(), "UTF-8")
                + "&redirect_uri=" + URLEncoder.encode(config.getRedirectUri(), "UTF-8");

        OutputStream os = conn.getOutputStream();
        os.write(params.getBytes("UTF-8"));
        os.close();

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            LOG.error("Token endpoint returned HTTP {}", responseCode);
            InputStream es = conn.getErrorStream();
            if (es != null) {
                Scanner s = new Scanner(es, "UTF-8").useDelimiter("\\A");
                LOG.error("Token endpoint error: {}", s.hasNext() ? s.next() : "");
                s.close();
            }
            conn.disconnect();
            return null;
        }

        Scanner scanner = new Scanner(conn.getInputStream(), "UTF-8").useDelimiter("\\A");
        String responseBody = scanner.hasNext() ? scanner.next() : "";
        scanner.close();
        conn.disconnect();

        return parseTokenResponse(responseBody);
    }

    private TokenResponse parseTokenResponse(String json) {
        TokenResponse tr = new TokenResponse();
        tr.idToken = extractJsonString(json, "id_token");
        tr.accessToken = extractJsonString(json, "access_token");
        tr.refreshToken = extractJsonString(json, "refresh_token");
        return tr;
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int keyIdx = json.indexOf(search);
        if (keyIdx < 0) {
            return null;
        }
        int valueStart = json.indexOf("\"", keyIdx + search.length());
        if (valueStart < 0) {
            return null;
        }
        valueStart++;
        int valueEnd = json.indexOf("\"", valueStart);
        if (valueEnd < 0) {
            return null;
        }
        return json.substring(valueStart, valueEnd);
    }

    @Override
    public void destroy() {
    }

    private static class TokenResponse {
        String idToken;
        String accessToken;
        String refreshToken;
    }
}
