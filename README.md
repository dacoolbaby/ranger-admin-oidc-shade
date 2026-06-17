# Ranger Admin OIDC Shade

Drop-in OIDC/OAuth2 authentication module for Apache Ranger Admin 2.8.0.

Adds **OpenID Connect** login support (Microsoft Entra ID, Keycloak, Okta, ...) to Ranger Admin **without modifying any Ranger source code**.

## Quick Start

```bash
# 1. Build
mvn clean package -DskipTests
# → target/ranger-admin-oidc-shade-2.8.0.jar

# 2. Deploy (just add 1 JAR, no replacements)
cp target/ranger-admin-oidc-shade-2.8.0.jar \
   <RANGER_HOME>/ews/webapp/WEB-INF/lib/

# 3. Configure (add to ranger-admin-site.xml)
#    See ranger-admin-site.xml.template for full example

# 4. Restart
ranger-admin restart
```

## Features

| Feature | Description |
|---------|-------------|
| **Authorization Code Flow** | Browser-based login with redirect to IdP |
| **Bearer Token Auth** | API access via `Authorization: Bearer <token>` |
| **JWKS Validation** | JWT signature verification with RS256/ES256 + key rotation |
| **Login Page Button** | Auto-injects "Login with ..." button into `/login.jsp` |
| **Auto-Provisioning** | Creates Ranger users on first login (`auto-create-user=true`) |
| **CSRF Protection** | State/nonce stored in HTTP Session (not cookie) |
| **MS Entra ID Ready** | Pre-configured template for Azure AD / Entra ID |
| **Multi-Provider** | Examples for Entra ID, Keycloak, Okta |
| **Zero Conflicts** | Verified against `apache/ranger:2.8.0` Docker image |

## Minimal Configuration (MS Entra ID)

```xml
<property>
    <name>ranger.oidc.enabled</name>
    <value>true</value>
</property>
<property>
    <name>ranger.oidc.issuer-uri</name>
    <value>https://login.microsoftonline.com/{tenant-id}/v2.0</value>
</property>
<property>
    <name>ranger.oidc.client-id</name>
    <value>{entra-app-client-id}</value>
</property>
<property>
    <name>ranger.oidc.client-secret</name>
    <value>{entra-app-client-secret}</value>
</property>
<property>
    <name>ranger.oidc.jwks-uri</name>
    <value>https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys</value>
</property>
<property>
    <name>ranger.oidc.auth-endpoint</name>
    <value>https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize</value>
</property>
<property>
    <name>ranger.oidc.token-endpoint</name>
    <value>https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token</value>
</property>
<property>
    <name>ranger.oidc.redirect-uri</name>
    <value>https://ranger-admin.example.com:6182/login/oidc/callback</value>
</property>
```

## Architecture

```
Browser / API Client
        │
        ▼
┌─────────────────────────────────────┐
│ ① OIDC Filter (Servlet level)       │  ← dynamically injected before
│   - /oidc/init        → redirect    │    springSecurityFilterChain
│   - /login/oidc/callback → exchange │
│   - Bearer token      → validate    │
│   - Cookie token      → validate    │
│   - login.jsp         → inject btn  │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│ ② Spring Security Filter Chain       │
│   - SecurityContextPersistenceFilter  │
│   - ssoAuthenticationFilter (skipped)│
│   - FORM_LOGIN_FILTER (skipped)      │
│   - RangerSecurityContextFormation   │  ← session + audit trail
└─────────────────────────────────────┘
        │
        ▼
    Ranger Admin
```

## Configuration Reference

| Property | Default | Description |
|----------|---------|-------------|
| `ranger.oidc.enabled` | `false` | Enable/disable OIDC |
| `ranger.oidc.issuer-uri` | — | IdP issuer URI |
| `ranger.oidc.client-id` | — | OIDC client ID |
| `ranger.oidc.client-secret` | — | OIDC client secret |
| `ranger.oidc.jwks-uri` | — | JWKS endpoint for signature verification |
| `ranger.oidc.auth-endpoint` | derived | Authorization endpoint |
| `ranger.oidc.token-endpoint` | derived | Token exchange endpoint |
| `ranger.oidc.redirect-uri` | — | Post-login callback URL |
| `ranger.oidc.scope` | `openid profile email groups` | Requested scopes |
| `ranger.oidc.username-claim` | `preferred_username` | JWT claim for login ID |
| `ranger.oidc.groups-claim` | `groups` | JWT claim for group membership |
| `ranger.oidc.admin-groups` | — | Groups granted `ROLE_SYS_ADMIN` (comma-separated) |
| `ranger.oidc.auto-create-user` | `true` | Auto-create Ranger user on first login |
| `ranger.oidc.provider-name` | `OIDC Provider` | Display name on login button |
| `ranger.oidc.cookie-name` | `ranger_oidc_token` | Session cookie name |
| `ranger.oidc.browser.useragent` | `Mozilla,Opera,AppleWebKit` | Browser UA prefixes |

## Files

```
ranger-admin-oidc-shade/
├── README.md
├── DEPLOY.md                              ← full deployment guide
├── pom.xml
└── src/
    └── main/
        ├── java/org/apache/ranger/security/oidc/
        │   ├── RangerOidcSecurityConfig.java    ← auto-scanned @Configuration
        │   ├── OidcAuthenticationFilter.java     ← main servlet filter
        │   ├── OidcTokenValidator.java           ← JWT/JWKS validation
        │   ├── OidcConfiguration.java            ← config loader
        │   ├── OidcAuthenticationProvider.java   ← Spring Security provider
        │   └── OidcUserDetails.java              ← UserDetails impl
        └── resources/
            ├── META-INF/spring/
            │   └── ranger-oidc-security.xml      ← alt XML config
            ├── oidc-default.properties
            └── ranger-admin-site.xml.template    ← full config template
```

## Test Coverage

```
103 tests, 0 failures
Instruction coverage: >70%
Branch coverage: >60%
```

## License

Apache License 2.0 — same as Apache Ranger.
