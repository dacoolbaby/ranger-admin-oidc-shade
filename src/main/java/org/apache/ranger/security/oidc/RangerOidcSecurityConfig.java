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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

/**
 * Spring configuration for the OIDC authentication shade module.
 *
 * This configuration is automatically detected by Ranger's component scan
 * (which covers {@code org.apache.ranger} and its sub-packages).
 *
 * When {@code ranger.oidc.enabled=true}, the OIDC authentication filter
 * is registered as a servlet filter before the Spring Security filter chain.
 *
 * <h3>Runtime Integration with Ranger</h3>
 * At runtime, the filter sets {@code request.setAttribute("ssoEnabled", true)}
 * so that Ranger's {@code RangerSecurityContextFormationFilter} uses
 * {@code AUTH_TYPE_SSO} (value 3) for audit trail purposes. This also
 * triggers Ranger's auto-provisioning logic in {@code SessionMgr}.
 */
@Configuration
public class RangerOidcSecurityConfig
        implements ApplicationContextAware, ServletContextAware,
                   ApplicationListener<ContextRefreshedEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(RangerOidcSecurityConfig.class);

    /** Default role assigned to OIDC users. */
    private static final String DEFAULT_ROLE = "ROLE_USER";

    private ApplicationContext applicationContext;
    private ServletContext servletContext;
    private boolean filterRegistered = false;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if (event.getApplicationContext().getParent() == null && !filterRegistered) {
            registerOidcFilter();
        }
    }

    private synchronized void registerOidcFilter() {
        if (filterRegistered || servletContext == null) {
            return;
        }

        OidcConfiguration config = oidcConfiguration();

        if (!config.isEnabled()) {
            LOG.info("OIDC authentication is disabled. Filter not registered.");
            filterRegistered = true;
            return;
        }

        try {
            OidcTokenValidator tokenValidator = oidcTokenValidator(config);
            OidcAuthenticationProvider authProvider = oidcAuthenticationProvider();
            OidcAuthenticationFilter filter = oidcAuthenticationFilter(config, tokenValidator, authProvider);

            // Set up authority resolver that uses Ranger's UserMgr if available
            authProvider.setAuthorityResolver(createAuthorityResolver());

            // Register the OIDC filter before springSecurityFilterChain
            FilterRegistration.Dynamic registration = servletContext.addFilter(
                    "oidcAuthenticationFilter", filter);
            registration.addMappingForUrlPatterns(
                    EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD,
                               DispatcherType.ASYNC),
                    false, // isMatchAfter=false → insert before existing filters
                    "/*");
            registration.setAsyncSupported(true);

            filterRegistered = true;
            LOG.info("OIDC authentication filter registered as 'oidcAuthenticationFilter'");

        } catch (Exception e) {
            LOG.error("Failed to register OIDC authentication filter: {}", e.getMessage(), e);
        }
    }

    /**
     * Creates an authority resolver that tries to use Ranger's UserMgr
     * bean (via reflection) if available at runtime.
     */
    private OidcAuthenticationProvider.AuthorityResolver createAuthorityResolver() {
        return new OidcAuthenticationProvider.AuthorityResolver() {
            @Override
            public Collection<? extends GrantedAuthority> resolveAuthorities(
                    String loginId, List<String> oidcGroups) {

                List<GrantedAuthority> authorities = new ArrayList<>();

                // Check for admin groups from config
                List<String> adminGroups = oidcConfiguration().getAdminGroups();
                if (!adminGroups.isEmpty() && oidcGroups != null) {
                    for (String group : oidcGroups) {
                        if (adminGroups.contains(group)) {
                            authorities.add(new SimpleGrantedAuthority("ROLE_SYS_ADMIN"));
                            return authorities;
                        }
                    }
                }

                // Try to use Ranger's UserMgr to resolve roles from database
                try {
                    Object userMgrBean = applicationContext.getBean("userMgr");
                    java.lang.reflect.Method getRolesMethod =
                            userMgrBean.getClass().getMethod("getRolesByLoginId", String.class);
                    @SuppressWarnings("unchecked")
                    Collection<String> roles =
                            (Collection<String>) getRolesMethod.invoke(userMgrBean, loginId);
                    if (roles != null && !roles.isEmpty()) {
                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority(role));
                        }
                        LOG.debug("Resolved roles from UserMgr for {}: {}", loginId, roles);
                        return authorities;
                    }
                } catch (Exception e) {
                    LOG.debug("Could not resolve roles via UserMgr for {}: {}", loginId, e.getMessage());
                }

                // Default role
                authorities.add(new SimpleGrantedAuthority(DEFAULT_ROLE));
                return authorities;
            }
        };
    }

    @Bean
    public OidcConfiguration oidcConfiguration() {
        return new OidcConfiguration();
    }

    @Bean
    public OidcTokenValidator oidcTokenValidator(OidcConfiguration config) {
        return new OidcTokenValidator(config);
    }

    @Bean
    public OidcAuthenticationProvider oidcAuthenticationProvider() {
        return new OidcAuthenticationProvider();
    }

    @Bean
    public OidcAuthenticationFilter oidcAuthenticationFilter(
            OidcConfiguration config,
            OidcTokenValidator tokenValidator,
            OidcAuthenticationProvider authProvider) {
        return new OidcAuthenticationFilter(config, tokenValidator, authProvider);
    }
}
