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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.*;

public class OidcAuthenticationProviderTest {

    private OidcAuthenticationProvider provider;

    @Before
    public void setUp() {
        provider = new OidcAuthenticationProvider();
    }

    @Test
    public void testSupportsUsernamePasswordAuthenticationToken() {
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    public void testSupportsAuthenticationInterface() {
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    public void testAuthenticateNullReturnsNull() {
        assertNull(provider.authenticate(null));
    }

    @Test
    public void testAuthenticateWithoutResolverReturnsAsIs() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        UserDetails principal = new User("testuser", "", authorities);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(principal, "", authorities);

        Authentication result = provider.authenticate(token);
        assertNotNull(result);
        assertEquals("testuser", result.getName());
        assertTrue(result.isAuthenticated());
        assertEquals(1, result.getAuthorities().size());
        assertTrue(result.getAuthorities().iterator().next().getAuthority().equals("ROLE_USER"));
    }

    @Test
    public void testAuthenticateWithResolverReturnsResolvedAuthorities() {
        OidcAuthenticationProvider.AuthorityResolver resolver =
                new OidcAuthenticationProvider.AuthorityResolver() {
                    @Override
                    public Collection<? extends GrantedAuthority> resolveAuthorities(
                            String loginId, List<String> oidcGroups) {
                        List<GrantedAuthority> auths = new ArrayList<>();
                        auths.add(new SimpleGrantedAuthority("ROLE_SYS_ADMIN"));
                        auths.add(new SimpleGrantedAuthority("ROLE_USER"));
                        return auths;
                    }
                };

        provider.setAuthorityResolver(resolver);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails principal = new User("admin", "", authorities);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(principal, "", authorities);

        Authentication result = provider.authenticate(token);
        assertNotNull(result);
        assertEquals("admin", result.getName());
        assertTrue(result.isAuthenticated());
        assertEquals(2, result.getAuthorities().size());

        // Verify both roles are present
        boolean hasSysAdmin = false;
        boolean hasUser = false;
        for (GrantedAuthority ga : result.getAuthorities()) {
            if ("ROLE_SYS_ADMIN".equals(ga.getAuthority())) hasSysAdmin = true;
            if ("ROLE_USER".equals(ga.getAuthority())) hasUser = true;
        }
        assertTrue(hasSysAdmin);
        assertTrue(hasUser);
    }

    @Test
    public void testAuthenticateWithResolverNullAuthoritiesFallsBack() {
        OidcAuthenticationProvider.AuthorityResolver resolver =
                new OidcAuthenticationProvider.AuthorityResolver() {
                    @Override
                    public Collection<? extends GrantedAuthority> resolveAuthorities(
                            String loginId, List<String> oidcGroups) {
                        return null;
                    }
                };

        provider.setAuthorityResolver(resolver);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails principal = new User("testuser", "", authorities);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(principal, "", authorities);

        Authentication result = provider.authenticate(token);
        assertNotNull(result);
        assertEquals("testuser", result.getName());
        assertTrue(result.isAuthenticated());
        assertEquals(1, result.getAuthorities().size());
    }

    @Test
    public void testAuthenticateWithResolverEmptyAuthoritiesFallsBack() {
        OidcAuthenticationProvider.AuthorityResolver resolver =
                new OidcAuthenticationProvider.AuthorityResolver() {
                    @Override
                    public Collection<? extends GrantedAuthority> resolveAuthorities(
                            String loginId, List<String> oidcGroups) {
                        return new ArrayList<>();
                    }
                };

        provider.setAuthorityResolver(resolver);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails principal = new User("testuser", "", authorities);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(principal, "", authorities);

        // Empty list from resolver falls back to original
        Authentication result = provider.authenticate(token);
        assertNotNull(result);
        assertEquals(1, result.getAuthorities().size());
    }

    @Test
    public void testDefaultResolverReturnsRoleUser() {
        OidcAuthenticationProvider.AuthorityResolver resolver =
                OidcAuthenticationProvider.defaultResolver();
        Collection<? extends GrantedAuthority> result = resolver.resolveAuthorities(
                "anyuser", Arrays.asList("some-group"));
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("ROLE_USER", result.iterator().next().getAuthority());
    }

    @Test
    public void testUnsupportedAuthentication() {
        Authentication unauthenticated =
                new UsernamePasswordAuthenticationToken("user", "pass");
        // Not authenticated, should return null
        assertNull(provider.authenticate(unauthenticated));
    }

    @Test
    public void testDetailsArePreserved() {
        Object details = new Object(); // WebAuthenticationDetails would be used in real scenario
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        UserDetails principal = new User("testuser", "", authorities);
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(principal, "", authorities);
        token.setDetails(details);

        Authentication result = provider.authenticate(token);
        assertNotNull(result);
        assertSame(details, result.getDetails());
    }
}
