# Task: Create ranger-admin-oidc-shade Module

## Background
Apache Ranger Admin currently lacks native OIDC (OpenID Connect) authentication support.
The goal is to create a Maven shade JAR (ranger-admin-oidc-shade) that patches/extends
ranger-admin to support OIDC login, without modifying the original ranger-admin source.

## Step 1: Analyze the Ranger Admin Source Code

First, explore and understand the existing authentication architecture:

1. Clone or locate the ranger source code (assume it's available at ./ranger or fetch from
   https://github.com/apache/ranger)

2. Read and analyze the following key files:
   - security-admin/src/main/java/org/apache/ranger/security/web/filter/RangerSSOAuthenticationFilter.java
   - security-admin/src/main/java/org/apache/ranger/security/web/authentication/RangerAuthenticationProvider.java
   - security-admin/src/main/webapp/WEB-INF/webapp-security.xml  (or Spring Security config)
   - security-admin/src/main/java/org/apache/ranger/biz/SessionMgr.java
   - security-admin/src/main/java/org/apache/ranger/common/RangerConfigUtil.java
   - security-admin/pom.xml  (to understand current dependencies)

3. Identify:
   - How authentication filters are registered (filter chain order)
   - How the current Knox SSO / Kerberos auth flows work
   - What UserDetails / Principal objects are used
   - Spring Security version in use
   - Where ranger-admin.properties / ranger.cfg configs are loaded

## Step 2: Design the OIDC Shade Module

Create a new Maven module `ranger-admin-oidc-shade` with the following structure:
ranger-admin-oidc-shade/

├── pom.xml

└── src/

└── main/

├── java/

│   └── org/apache/ranger/security/oidc/

│       ├── OidcAuthenticationFilter.java

│       ├── OidcAuthenticationProvider.java

│       ├── OidcUserDetails.java

│       ├── OidcTokenValidator.java

│       ├── OidcConfiguration.java

│       └── RangerOidcSecurityConfig.java

└── resources/

├── META-INF/

│   └── spring/

│       └── ranger-oidc-security.xml

└── oidc-default.properties

## Step 3: Implementation Requirements

### pom.xml
- Parent: align with ranger's root pom (use same Spring Security version)
- Shade plugin: relocate `org.springframework.security.oauth2` to avoid conflicts
- Include: spring-security-oauth2-client, spring-security-oauth2-jose, nimbus-jose-jwt
- Scope all ranger-admin deps as `provided`
- Output: a single fat JAR deployable to ranger-admin/ews/webapp/WEB-INF/lib/

### OidcAuthenticationFilter.java
Implement a `javax.servlet.Filter` (or Spring's `OncePerRequestFilter`) that:
- Intercepts requests and checks for OIDC Bearer token in Authorization header
  OR checks for OIDC session cookie (configurable)
- Validates token via OidcTokenValidator
- On success: sets SecurityContextHolder with authenticated token
- On failure: either redirects to OIDC provider (browser flow) or returns 401 (API flow)
- Has lower order than existing RangerSSOAuthenticationFilter so it runs first
- Reads config from ranger-admin.properties with prefix `ranger.oidc.*`

### OidcTokenValidator.java
- Uses Nimbus JOSE+JWT to validate JWT tokens
- Supports JWKS URI (fetches and caches public keys)
- Validates: issuer, audience, expiry, signature
- Extracts claims: sub, email, groups/roles claim (configurable claim name)
- Supports both RS256 and ES256
- Implements JWKS key rotation (refresh on unknown kid)

### OidcAuthenticationProvider.java
- Implements Spring Security's `AuthenticationProvider`
- Maps OIDC claims to Ranger's internal UserDetails
- Maps OIDC groups claim → Ranger roles (configurable mapping)
- Calls Ranger's existing UserMgr to auto-provision users if `ranger.oidc.auto-create-user=true`

### OidcConfiguration.java
Load from ranger-admin.properties:
ranger.oidc.enabled=true

ranger.oidc.issuer-uri=https://your-idp.example.com

ranger.oidc.client-id=ranger-admin

ranger.oidc.client-secret=<secret>

ranger.oidc.jwks-uri=https://your-idp.example.com/jwks

ranger.oidc.redirect-uri=https://ranger-admin:6080/login/oidc/callback

ranger.oidc.scope=openid profile email groups

ranger.oidc.groups-claim=groups

ranger.oidc.admin-groups=ranger-admins

ranger.oidc.auto-create-user=true

ranger.oidc.cookie-name=ranger_oidc_token

ranger.oidc.token-header=Authorization
### RangerOidcSecurityConfig.java
- A `@Configuration` + `@ConditionalOnProperty(prefix="ranger.oidc", name="enabled", havingValue="true")`
- Registers OidcAuthenticationFilter into the existing Spring Security filter chain
- Must insert BEFORE `RangerSSOAuthenticationFilter` if present
- Registers OidcAuthenticationProvider
- Configures logout to also invalidate OIDC session (RP-Initiated Logout)

## Step 4: Integration Points

After reading the source, handle these specific integration concerns:

1. **Filter ordering**: Find the exact `FilterRegistrationBean` or `web.xml` filter order
   in ranger-admin and ensure OIDC filter gets order = (existing_sso_order - 1)

2. **Session management**: Check if ranger uses `SessionMgr.java` for session tracking —
   if so, call the same `addSession()` method after OIDC auth so Ranger's audit trail works

3. **User sync**: If ranger has `UserSyncService` or calls to `XUserService`, ensure
   OIDC-authed users get properly registered (check `XUserMgr.createServiceConfigUser`)

4. **Admin redirect**: Ranger Admin's login page (login.jsp or React app) should detect
   OIDC enabled and show "Login with SSO" button — add a `/oidc/init` endpoint that
   triggers authorization_code flow redirect

5. **Callback endpoint**: Create a `/login/oidc/callback` Spring MVC controller that:
   - Exchanges authorization code for tokens
   - Validates ID token
   - Creates Ranger session
   - Redirects to Ranger home

## Step 5: Testing

Create integration test:
- `OidcTokenValidatorTest.java`: mock JWKS endpoint, test valid/expired/tampered tokens
- `OidcAuthenticationFilterTest.java`: mock HTTP request with Bearer token, verify
  SecurityContext is populated correctly
- `OidcConfigurationTest.java`: verify properties loading

## Step 6: Deployment Instructions

Generate a README.md explaining:
1. Build: `mvn clean package -pl ranger-admin-oidc-shade`
2. Deploy: copy shade JAR to `<ranger-admin>/ews/webapp/WEB-INF/lib/`
3. Configure: add `ranger.oidc.*` properties to `ranger-admin.properties`
4. Restart ranger-admin service

## Important Constraints

- Do NOT modify any existing ranger-admin source files
- All new classes must be in package `org.apache.ranger.security.oidc`
- Must be compatible with both Ranger 2.3.x and 2.4.x (check which Spring Security version each uses)
- The shade JAR must work as a drop-in: just add to classpath + add config properties
- Handle the case where OIDC is disabled gracefully (all beans are no-ops)
- Log all OIDC auth events through Ranger's existing audit mechanism if available

## Start

Begin by reading the ranger-admin source files listed in Step 1 to understand the
existing auth architecture, then implement accordingly. Show me the pom.xml and
OidcAuthenticationFilter.java first.
