# Ranger Admin OIDC Shade Module - 部署与配置指南

## 构建

```bash
cd ranger-admin-oidc-shade
mvn clean package -DskipTests
```

产物：`target/ranger-admin-oidc-shade-2.8.0.jar`（约 3.1 MB）

## 部署

### 部署方式：仅需添加 1 个 JAR

**无需替换、无需删除任何已有 JAR。** 只需将 shade JAR 放入 `WEB-INF/lib/` 即可。

```
需添加：
  ✅ ranger-admin-oidc-shade-2.8.0.jar   （新增，3.1 MB）

需替换：
  无

需删除：
  无
```

### 依赖兼容性说明（已通过 Docker 镜像 `apache/ranger:2.8.0` 校验）

| 依赖 | 处理方式 | 冲突 |
|------|----------|------|
| `spring-security-oauth2-*` | relocate 到 `shaded.` 包 | ✅ 无 |
| `spring-core/util/beans/aop` | 排除，使用 Ranger 的 `5.3.39` | ✅ 无 |
| `nimbus-jose-jwt` | provided，使用 Ranger 的 `10.0.1` | ✅ 无 |
| `nimbus-oauth2-oidc-sdk` | 打进 shade JAR（Ranger 无此包） | ✅ 无 |
| `json-smart` (`net.minidev.json`) | 排除，使用 Ranger 的 `2.4.10` | ✅ 无 |
| `accessors-smart` (`net.minidev.asm`) | 排除，使用 Ranger 的 `2.4.9` | ✅ 无 |
| `asm` (`org.objectweb.asm`) | 排除，使用 Ranger 的 `9.3` | ✅ 无 |
| `jackson-*` | provided，使用 Ranger 的 `2.17.2` | ✅ 无 |
| `commons-lang3` | provided，使用 Ranger 的 `3.19.0` | ✅ 无 |
| `slf4j-api` | provided，使用 Ranger 的 `2.0.7` | ✅ 无 |
| `javax.servlet-api` | provided，使用容器自带 | ✅ 无 |

> 校验命令：`docker pull apache/ranger:2.8.0`，逐一比对 `WEB-INF/lib/` 下的 JAR 与 shade JAR 内的 class 包路径。

### 直接部署（物理机/虚拟机）

```bash
cp target/ranger-admin-oidc-shade-2.8.0.jar \
   <RANGER_HOME>/ews/webapp/WEB-INF/lib/

# 重启 Ranger Admin
ranger-admin restart
```

### Docker 镜像部署

基于已有的 Ranger Admin 镜像，通过挂载或构建新镜像的方式添加 JAR：

**方式一：Volume 挂载（快速验证）**

```bash
docker run -d \
  -v /path/to/ranger-admin-oidc-shade-2.8.0.jar:/opt/ranger/ews/webapp/WEB-INF/lib/ranger-admin-oidc-shade-2.8.0.jar \
  <ranger-admin-image>
```

**方式二：Dockerfile 构建新镜像**

```dockerfile
FROM <已有的-ranger-admin-image>

# 仅添加 OIDC shade JAR，无需修改其他文件
COPY ranger-admin-oidc-shade-2.8.0.jar \
     /opt/ranger/ews/webapp/WEB-INF/lib/ranger-admin-oidc-shade-2.8.0.jar

# 验证 JAR 已复制
RUN ls -la /opt/ranger/ews/webapp/WEB-INF/lib/ranger-admin-oidc-shade-2.8.0.jar
```

```bash
docker build -t ranger-admin-oidc:2.8.0 .
docker run -d ranger-admin-oidc:2.8.0
```

**方式三：Kubernetes ConfigMap / Init Container**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ranger-oidc-jar
binaryData:
  ranger-admin-oidc-shade-2.8.0.jar: |
    <base64-encoded-jar>
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: ranger-admin
        image: <ranger-admin-image>
        volumeMounts:
        - name: oidc-jar
          mountPath: /opt/ranger/ews/webapp/WEB-INF/lib/ranger-admin-oidc-shade-2.8.0.jar
          subPath: ranger-admin-oidc-shade-2.8.0.jar
      volumes:
      - name: oidc-jar
        configMap:
          name: ranger-oidc-jar
```

## 配置

在 `ranger-admin-site.xml`（路径：`<RANGER_HOME>/ews/webapp/WEB-INF/classes/conf.dist/ranger-admin-site.xml`）中添加以下属性：

```xml
<property>
    <name>ranger.oidc.enabled</name>
    <value>true</value>
</property>

<property>
    <name>ranger.oidc.issuer-uri</name>
    <value>https://keycloak.example.com/realms/myrealm</value>
</property>

<property>
    <name>ranger.oidc.client-id</name>
    <value>ranger-admin</value>
</property>

<property>
    <name>ranger.oidc.client-secret</name>
    <value>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</value>
</property>

<property>
    <name>ranger.oidc.jwks-uri</name>
    <value>https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs</value>
</property>

<property>
    <name>ranger.oidc.redirect-uri</name>
    <value>https://ranger-admin.example.com:6182/login/oidc/callback</value>
</property>
```

## 完整配置项

| 属性 | 默认值 | 说明 |
|------|--------|------|
| `ranger.oidc.enabled` | `false` | 启用/禁用 OIDC 认证 |
| `ranger.oidc.issuer-uri` | - | OIDC Provider Issuer URI |
| `ranger.oidc.client-id` | - | OIDC 客户端 ID |
| `ranger.oidc.client-secret` | - | OIDC 客户端密钥 |
| `ranger.oidc.jwks-uri` | - | JWKS 公钥端点（用于验证 JWT 签名） |
| `ranger.oidc.redirect-uri` | - | 授权码回调地址 |
| `ranger.oidc.auth-endpoint` | 自动从 issuer-uri 推导 | 授权端点 |
| `ranger.oidc.token-endpoint` | 自动从 issuer-uri 推导 | Token 交换端点 |
| `ranger.oidc.userinfo-endpoint` | - | UserInfo 端点 |
| `ranger.oidc.end-session-endpoint` | - | RP-Initiated Logout 端点 |
| `ranger.oidc.scope` | `openid profile email groups` | 请求的 OIDC scope |
| `ranger.oidc.groups-claim` | `groups` | JWT 中包含用户组的 claim 名 |
| `ranger.oidc.admin-groups` | - | 拥有 `ROLE_SYS_ADMIN` 的 OIDC 组（逗号分隔） |
| `ranger.oidc.auto-create-user` | `true` | 首次登录时自动创建 Ranger 用户 |
| `ranger.oidc.cookie-name` | `ranger_oidc_token` | 存储 OIDC token 的 Cookie 名 |
| `ranger.oidc.token-header` | `Authorization` | Bearer token 请求头名 |
| `ranger.oidc.email-claim` | `email` | JWT 中 email 的 claim 名 |
| `ranger.oidc.username-claim` | `preferred_username` | JWT 中用户名的 claim 名 |
| `ranger.oidc.provider-name` | `OIDC Provider` | 登录页面按钮上显示的名称 |
| `ranger.oidc.browser.useragent` | `Mozilla,Opera,AppleWebKit` | 浏览器 User-Agent 前缀（逗号分隔） |

## MS Entra ID (Azure AD) 配置示例

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
    <value>{your-app-registration-client-id}</value>
</property>

<property>
    <name>ranger.oidc.client-secret</name>
    <value>{your-app-registration-client-secret}</value>
</property>

<property>
    <name>ranger.oidc.jwks-uri</name>
    <value>https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys</value>
</property>

<property>
    <name>ranger.oidc.redirect-uri</name>
    <value>https://ranger-admin.example.com:6182/login/oidc/callback</value>
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
    <name>ranger.oidc.username-claim</name>
    <value>preferred_username</value>
</property>

<property>
    <name>ranger.oidc.email-claim</name>
    <value>email</value>
</property>

<property>
    <name>ranger.oidc.provider-name</name>
    <value>Microsoft Entra ID</value>
</property>

<!-- MS Entra ID 默认返回 group IDs 而非 group 名称 -->
<!-- 如需 group 名称，在 Entra App Registration 中配置 Groups claim 为 "Group name" -->
<property>
    <name>ranger.oidc.groups-claim</name>
    <value>groups</value>
</property>
```

### Entra ID App Registration 配置要点

1. 在 Azure Portal > Entra ID > App registrations 中创建应用
2. **Redirect URI**: 添加 Web 平台，URI 设为 `https://<ranger-host>:6182/login/oidc/callback`
3. **Implicit grant**: 不需要（使用 Authorization code flow）
4. **Certificates & secrets**: 创建一个 client secret，填入 `ranger.oidc.client-secret`
5. **Token configuration**: 添加可选 claims:
   - `email` (ID token)
   - `preferred_username` (ID token)
   - `groups` (ID token) — 选择 "Group ID" 或 "DNSDomain\sAMAccountName"（如需要组名）
6. **API permissions**: 至少需要 `openid`, `profile`, `email`, `User.Read`

## 认证流程

### 浏览器用户（Authorization Code Flow）

1. 用户访问 Ranger Admin，未认证
2. 访问 `/login.jsp` 页面，OIDC 过滤器注入 "Login with Microsoft Entra ID" 按钮
3. 用户点击按钮 → 跳转 `/oidc/init` → 重定向到 MS Entra 登录页
4. 用户在 Entra ID 完成登录（含 MFA 等） → 重定向回 `/login/oidc/callback?code=...`
5. 过滤器用授权码换取 ID Token + Access Token
6. 验证 ID Token（签名、过期时间、issuer）
7. 将会话信息存入 HTTP Session → 重定向到 Ranger 首页

### API 客户端（Bearer Token）

```
GET /service/public/v2/api/policies
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

过滤器验证 Bearer token，通过后直接放行。

### API 未认证响应

API 请求携带无效 token 时返回：
```
HTTP 401 Unauthorized
{"error":"invalid_token"}
```

### AJAX 请求

前端 AJAX 请求未认证时返回：
```
HTTP 419 Authentication Timeout
X-Rngr-Redirect-Url: /oidc/init
```

## 登录页面集成

OIDC 过滤器会自动在 Ranger 的 `login.jsp` 页面中注入 "Login with {provider-name}" 按钮，**无需修改 Ranger 源文件**（通过 response wrapper 注入 HTML）。

### 效果示意

当用户访问 `/login.jsp` 时，会在原有登录表单下方看到 OIDC 登录按钮：

```
┌─────────────────────────────────┐
│        Ranger Admin Login       │
│                                 │
│  ┌──────────┐ ┌──────────────┐  │
│  │ Username │ │              │  │
│  └──────────┘ └──────────────┘  │
│  ┌──────────┐ ┌──────────────┐  │
│  │ Password │ │              │  │
│  └──────────┘ └──────────────┘  │
│          [   Login   ]          │
│                                 │
│  ────────── or ────────────     │  ← 分隔线
│                                 │
│  ┌───────────────────────────┐  │
│  │  Login with Microsoft     │  │  ← 过滤器自动注入
│  │       Entra ID            │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

- 按钮样式为蓝色（`#0078D4`），hover 时变深
- 配置 `ranger.oidc.provider-name` 自定义按钮文字
- 按钮链接到 `/oidc/init`，触发 Authorization Code Flow

### 三种访问入口

| 入口 | URL | 说明 |
|------|-----|------|
| 登录页面（带 OIDC 按钮） | `/login.jsp` | 用户看到本地登录表单 + OIDC 按钮，可选择登录方式 |
| 直达 OIDC 登录 | `/oidc/init` | 直接跳转到 IdP 认证页面（可设为书签） |
| 本地账号登录 | `/locallogin` | 绕过 OIDC，仅显示用户名密码登录 |

## 与 Ranger 内部集成机制

- **审计日志**：过滤器设置 `request.ssoEnabled=true`，触发 `AUTH_TYPE_SSO`（值为 3）审计类型
- **用户自动创建**：通过 `ssoEnabled=true` 标记，`SessionMgr.getSSOSpnegoAuthCheckForAPI()` 自动调用 `XUserMgr.createServiceConfigUser()`
- **角色映射**：使用反射调用 `UserMgr.getRolesByLoginId()` 从 Ranger 数据库获取角色；`admin-groups` 中配置的 OIDC 组成员直接获得 `ROLE_SYS_ADMIN`
- **会话管理**：认证信息存储在 `HttpSession` 的 `SPRING_SECURITY_CONTEXT` key 下，与 Spring Security 的 `SecurityContextPersistenceFilter` 无缝集成

## 验证

构建完成后可通过以下命令检查 JAR 内容：

```bash
jar tf target/ranger-admin-oidc-shade-2.8.0.jar | grep -E "Oidc|oidc"
```

预期输出：
```
org/apache/ranger/security/oidc/OidcAuthenticationFilter.class
org/apache/ranger/security/oidc/OidcAuthenticationProvider.class
org/apache/ranger/security/oidc/OidcConfiguration.class
org/apache/ranger/security/oidc/OidcTokenValidator.class
org/apache/ranger/security/oidc/OidcUserDetails.class
org/apache/ranger/security/oidc/RangerOidcSecurityConfig.class
oidc-default.properties
```
