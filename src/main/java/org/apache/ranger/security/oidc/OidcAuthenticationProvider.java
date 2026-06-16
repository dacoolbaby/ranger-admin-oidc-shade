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
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * AuthenticationProvider for OIDC-authenticated tokens.
 *
 * Maps OIDC claims to Ranger's internal UserDetails and authorities.
 * At runtime, Ranger's UserMgr bean resolves roles from the database
 * when available.
 *
 * This class avoids compile-time dependencies on Ranger internal classes
 * by accepting a configurable authority resolver callback.
 */
public class OidcAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

    /** Default role assigned to new OIDC users. */
    private static final String DEFAULT_ROLE = "ROLE_USER";

    /** Configurable authority resolver (set at runtime by Spring configuration). */
    private AuthorityResolver authorityResolver;

    public OidcAuthenticationProvider() {
    }

    /**
     * Functional interface for resolving authorities at runtime.
     * Implementations can use Ranger's UserMgr to look up roles from the database.
     */
    public interface AuthorityResolver {
        Collection<? extends GrantedAuthority> resolveAuthorities(String loginId, List<String> oidcGroups);
    }

    public void setAuthorityResolver(AuthorityResolver authorityResolver) {
        this.authorityResolver = authorityResolver;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            return null;
        }

        // For UsernamePasswordAuthenticationToken created by the filter,
        // pass through with resolved authorities (SSO pass-through pattern)
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            if (authentication.isAuthenticated()) {
                // Resolve authorities if we have a resolver
                if (authorityResolver != null) {
                    String loginId = authentication.getName();
                    @SuppressWarnings("unchecked")
                    Collection<? extends GrantedAuthority> authorities =
                            authorityResolver.resolveAuthorities(loginId, java.util.Collections.<String>emptyList());
                    if (authorities != null && !authorities.isEmpty()) {
                        UserDetails principal = new User(loginId, "", authorities);
                        UsernamePasswordAuthenticationToken result =
                                new UsernamePasswordAuthenticationToken(principal, "", authorities);
                        result.setDetails(authentication.getDetails());
                        LOG.debug("OIDC authentication with resolved authorities for: {}", loginId);
                        return result;
                    }
                }
                // Return as-is if no resolver or no authorities found
                return authentication;
            }
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Creates a default AuthorityResolver that uses the configured default role.
     */
    public static AuthorityResolver defaultResolver() {
        return new AuthorityResolver() {
            @Override
            public Collection<? extends GrantedAuthority> resolveAuthorities(
                    String loginId, List<String> oidcGroups) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(DEFAULT_ROLE));
                return authorities;
            }
        };
    }
}
