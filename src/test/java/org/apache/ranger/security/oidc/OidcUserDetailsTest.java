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

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

import static org.junit.Assert.*;

public class OidcUserDetailsTest {

    @Test
    public void testBasicConstruction() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        claims.put("email", "user@example.com");

        OidcUserDetails user = new OidcUserDetails(
                "user123", "user123", "user@example.com",
                Arrays.asList("group1", "group2"), claims, authorities);

        assertEquals("user123", user.getUsername());
        assertEquals("user123", user.getSubject());
        assertEquals("user@example.com", user.getEmail());
        assertEquals("", user.getPassword());
        assertTrue(user.isEnabled());
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
        assertTrue(user.isCredentialsNonExpired());
        assertEquals(1, user.getAuthorities().size());
        assertTrue(user.getAuthorities().iterator().next().getAuthority().equals("ROLE_USER"));
    }

    @Test
    public void testGroups() {
        List<String> groups = Arrays.asList("developers", "admins", "viewers");
        OidcUserDetails user = new OidcUserDetails(
                "user1", "sub1", "user1@example.com",
                groups, Collections.<String, Object>emptyMap(),
                Collections.<GrantedAuthority>emptyList());

        assertEquals(3, user.getGroups().size());
        assertTrue(user.getGroups().contains("developers"));
        assertTrue(user.getGroups().contains("admins"));
        assertTrue(user.getGroups().contains("viewers"));
    }

    @Test
    public void testNullGroupsDefaultsToEmpty() {
        OidcUserDetails user = new OidcUserDetails(
                "user1", "sub1", null,
                null, null,
                Collections.<GrantedAuthority>emptyList());

        assertNotNull(user.getGroups());
        assertTrue(user.getGroups().isEmpty());
    }

    @Test
    public void testNullClaimsDefaultsToEmpty() {
        OidcUserDetails user = new OidcUserDetails(
                "user1", "sub1", null,
                Collections.<String>emptyList(), null,
                Collections.<GrantedAuthority>emptyList());

        assertNotNull(user.getClaims());
        assertTrue(user.getClaims().isEmpty());
    }

    @Test
    public void testClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "user123");
        claims.put("email", "user@example.com");
        claims.put("preferred_username", "john.doe");
        claims.put("email_verified", true);
        claims.put("groups", Arrays.asList("group1", "group2"));

        OidcUserDetails user = new OidcUserDetails(
                "john.doe", "user123", "user@example.com",
                Collections.<String>emptyList(), claims,
                Collections.<GrantedAuthority>emptyList());

        Map<String, Object> storedClaims = user.getClaims();
        assertEquals("user123", storedClaims.get("sub"));
        assertEquals("user@example.com", storedClaims.get("email"));
        assertEquals("john.doe", storedClaims.get("preferred_username"));
        assertEquals(true, storedClaims.get("email_verified"));
    }

    @Test
    public void testMultipleAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_SYS_ADMIN"));
        authorities.add(new SimpleGrantedAuthority("ROLE_KEY_ADMIN"));

        OidcUserDetails user = new OidcUserDetails(
                "admin", "admin", "admin@example.com",
                Collections.<String>emptyList(), Collections.<String, Object>emptyMap(),
                authorities);

        Collection<? extends GrantedAuthority> result = user.getAuthorities();
        assertEquals(3, result.size());

        Set<String> authorityNames = new HashSet<>();
        for (GrantedAuthority ga : result) {
            authorityNames.add(ga.getAuthority());
        }
        assertTrue(authorityNames.contains("ROLE_USER"));
        assertTrue(authorityNames.contains("ROLE_SYS_ADMIN"));
        assertTrue(authorityNames.contains("ROLE_KEY_ADMIN"));
    }

    @Test
    public void testDifferentUsernameAndSubject() {
        OidcUserDetails user = new OidcUserDetails(
                "login-name", "sub-uuid-12345", "email@example.com",
                Collections.<String>emptyList(), Collections.<String, Object>emptyMap(),
                Collections.<GrantedAuthority>emptyList());

        assertEquals("login-name", user.getUsername());
        assertEquals("sub-uuid-12345", user.getSubject());
        assertEquals("email@example.com", user.getEmail());
    }
}
