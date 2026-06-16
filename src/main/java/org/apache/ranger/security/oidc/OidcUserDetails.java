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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * UserDetails implementation for OIDC-authenticated users.
 *
 * Holds the OIDC claims (sub, email, preferred_username, groups, etc.)
 * extracted from the ID token or UserInfo response.
 */
public class OidcUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final String subject;
    private final String email;
    private final List<String> groups;
    private final Map<String, Object> claims;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;

    public OidcUserDetails(String username, String subject, String email,
                           List<String> groups, Map<String, Object> claims,
                           Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.subject = subject;
        this.email = email;
        this.groups = groups != null ? groups : Collections.<String>emptyList();
        this.claims = claims != null ? claims : Collections.<String, Object>emptyMap();
        this.authorities = authorities;
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /** Returns the OIDC subject (sub) claim. */
    public String getSubject() {
        return subject;
    }

    /** Returns the email claim if available. */
    public String getEmail() {
        return email;
    }

    /** Returns the OIDC groups claim. */
    public List<String> getGroups() {
        return groups;
    }

    /** Returns all claims from the ID token / UserInfo. */
    public Map<String, Object> getClaims() {
        return claims;
    }
}
