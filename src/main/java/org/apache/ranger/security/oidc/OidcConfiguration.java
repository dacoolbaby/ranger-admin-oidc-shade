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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * Loads and holds OIDC configuration from ranger-admin-site.xml
 * and system properties with prefix {@code ranger.oidc.}.
 *
 * At runtime, Ranger's PropertiesUtil populates system properties and
 * makes them available. This class also loads from classpath resource
 * files for standalone testing.
 */
public class OidcConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(OidcConfiguration.class);

    /** Prefix for all OIDC configuration properties. */
    public static final String OIDC_PROP_PREFIX = "ranger.oidc.";

    // Property keys
    public static final String OIDC_ENABLED            = OIDC_PROP_PREFIX + "enabled";
    public static final String OIDC_ISSUER_URI         = OIDC_PROP_PREFIX + "issuer-uri";
    public static final String OIDC_CLIENT_ID          = OIDC_PROP_PREFIX + "client-id";
    public static final String OIDC_CLIENT_SECRET      = OIDC_PROP_PREFIX + "client-secret";
    public static final String OIDC_JWKS_URI           = OIDC_PROP_PREFIX + "jwks-uri";
    public static final String OIDC_REDIRECT_URI       = OIDC_PROP_PREFIX + "redirect-uri";
    public static final String OIDC_SCOPE              = OIDC_PROP_PREFIX + "scope";
    public static final String OIDC_GROUPS_CLAIM       = OIDC_PROP_PREFIX + "groups-claim";
    public static final String OIDC_ADMIN_GROUPS       = OIDC_PROP_PREFIX + "admin-groups";
    public static final String OIDC_AUTO_CREATE_USER   = OIDC_PROP_PREFIX + "auto-create-user";
    public static final String OIDC_COOKIE_NAME        = OIDC_PROP_PREFIX + "cookie-name";
    public static final String OIDC_TOKEN_HEADER       = OIDC_PROP_PREFIX + "token-header";
    public static final String OIDC_AUTH_ENDPOINT      = OIDC_PROP_PREFIX + "auth-endpoint";
    public static final String OIDC_TOKEN_ENDPOINT     = OIDC_PROP_PREFIX + "token-endpoint";
    public static final String OIDC_USERINFO_ENDPOINT  = OIDC_PROP_PREFIX + "userinfo-endpoint";
    public static final String OIDC_END_SESSION_ENDPOINT = OIDC_PROP_PREFIX + "end-session-endpoint";
    public static final String OIDC_EMAIL_CLAIM        = OIDC_PROP_PREFIX + "email-claim";
    public static final String OIDC_USERNAME_CLAIM     = OIDC_PROP_PREFIX + "username-claim";
    public static final String OIDC_BROWSER_USER_AGENTS = OIDC_PROP_PREFIX + "browser.useragent";
    public static final String OIDC_PROVIDER_NAME       = OIDC_PROP_PREFIX + "provider-name";

    // Default values
    public static final String DEFAULT_SCOPE               = "openid profile email groups";
    public static final String DEFAULT_GROUPS_CLAIM        = "groups";
    public static final String DEFAULT_COOKIE_NAME         = "ranger_oidc_token";
    public static final String DEFAULT_TOKEN_HEADER        = "Authorization";
    public static final String DEFAULT_EMAIL_CLAIM         = "email";
    public static final String DEFAULT_USERNAME_CLAIM      = "preferred_username";
    public static final String DEFAULT_BROWSER_USER_AGENTS  = "Mozilla,Opera,AppleWebKit";
    public static final String DEFAULT_PROVIDER_NAME        = "OIDC Provider";

    /** Properties loaded from resource files. */
    private final Properties properties = new Properties();

    private boolean enabled;
    private String issuerUri;
    private String clientId;
    private String clientSecret;
    private String jwksUri;
    private String redirectUri;
    private String scope;
    private String groupsClaim;
    private List<String> adminGroups;
    private boolean autoCreateUser;
    private String cookieName;
    private String tokenHeader;
    private String authEndpoint;
    private String tokenEndpoint;
    private String userinfoEndpoint;
    private String endSessionEndpoint;
    private String emailClaim;
    private String usernameClaim;
    private String providerName;
    private String[] browserUserAgents;

    public OidcConfiguration() {
        loadDefaults();
        loadConfiguration();
    }

    private void loadDefaults() {
        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("oidc-default.properties")) {
            if (is != null) {
                properties.load(is);
                LOG.debug("Loaded oidc-default.properties");
            }
        } catch (IOException e) {
            LOG.debug("Could not load oidc-default.properties: {}", e.getMessage());
        }
    }

    public void loadConfiguration() {
        // Load from system properties (populated by Ranger's PropertiesUtil at runtime)
        enabled = getBooleanProperty(OIDC_ENABLED, false);

        if (!enabled) {
            LOG.info("OIDC authentication is disabled");
            return;
        }

        issuerUri          = getProperty(OIDC_ISSUER_URI);
        clientId           = getProperty(OIDC_CLIENT_ID);
        clientSecret       = getProperty(OIDC_CLIENT_SECRET);
        jwksUri            = getProperty(OIDC_JWKS_URI);
        redirectUri        = getProperty(OIDC_REDIRECT_URI);
        scope              = getProperty(OIDC_SCOPE, DEFAULT_SCOPE);
        groupsClaim        = getProperty(OIDC_GROUPS_CLAIM, DEFAULT_GROUPS_CLAIM);
        cookieName         = getProperty(OIDC_COOKIE_NAME, DEFAULT_COOKIE_NAME);
        tokenHeader        = getProperty(OIDC_TOKEN_HEADER, DEFAULT_TOKEN_HEADER);
        authEndpoint       = getProperty(OIDC_AUTH_ENDPOINT);
        tokenEndpoint      = getProperty(OIDC_TOKEN_ENDPOINT);
        userinfoEndpoint   = getProperty(OIDC_USERINFO_ENDPOINT);
        endSessionEndpoint = getProperty(OIDC_END_SESSION_ENDPOINT);
        emailClaim         = getProperty(OIDC_EMAIL_CLAIM, DEFAULT_EMAIL_CLAIM);
        usernameClaim      = getProperty(OIDC_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM);
        providerName       = getProperty(OIDC_PROVIDER_NAME, DEFAULT_PROVIDER_NAME);
        autoCreateUser     = getBooleanProperty(OIDC_AUTO_CREATE_USER, true);

        String adminGroupsStr = getProperty(OIDC_ADMIN_GROUPS, "");
        adminGroups = StringUtils.isBlank(adminGroupsStr)
                ? Collections.<String>emptyList()
                : Arrays.asList(adminGroupsStr.split(","));

        String userAgents = getProperty(OIDC_BROWSER_USER_AGENTS, DEFAULT_BROWSER_USER_AGENTS);
        browserUserAgents = userAgents.split(",");

        LOG.info("OIDC configuration loaded: issuerUri={}, clientId={}, jwksUri={}, "
                        + "scope={}, groupsClaim={}, adminGroups={}, autoCreateUser={}, "
                        + "cookieName={}, tokenHeader={}",
                issuerUri, clientId, jwksUri, scope, groupsClaim, adminGroups,
                autoCreateUser, cookieName, tokenHeader);
    }

    /**
     * Gets a property value, checking system properties first (from Ranger's
     * PropertiesUtil), then our loaded defaults.
     */
    private String getProperty(String key, String defaultValue) {
        // System properties (set by Ranger's PropertiesUtil at runtime)
        String value = System.getProperty(key);
        if (value != null) {
            return value;
        }
        // Resource defaults
        value = properties.getProperty(key);
        if (value != null) {
            return value;
        }
        return defaultValue;
    }

    private String getProperty(String key) {
        return getProperty(key, null);
    }

    private boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = getProperty(key, null);
        if (value == null) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(value.trim());
    }

    // Getters
    public boolean isEnabled()                         { return enabled; }
    public String getIssuerUri()                       { return issuerUri; }
    public String getClientId()                        { return clientId; }
    public String getClientSecret()                    { return clientSecret; }
    public String getJwksUri()                         { return jwksUri; }
    public String getRedirectUri()                     { return redirectUri; }
    public String getScope()                           { return scope; }
    public String getGroupsClaim()                     { return groupsClaim; }
    public List<String> getAdminGroups()                { return adminGroups; }
    public boolean isAutoCreateUser()                  { return autoCreateUser; }
    public String getCookieName()                      { return cookieName; }
    public String getTokenHeader()                     { return tokenHeader; }
    public String getAuthEndpoint()                    { return authEndpoint; }
    public String getTokenEndpoint()                   { return tokenEndpoint; }
    public String getUserinfoEndpoint()                 { return userinfoEndpoint; }
    public String getEndSessionEndpoint()               { return endSessionEndpoint; }
    public String getEmailClaim()                      { return emailClaim; }
    public String getUsernameClaim()                   { return usernameClaim; }
    public String getProviderName()                    { return providerName; }
    public String[] getBrowserUserAgents()              { return browserUserAgents; }
}
