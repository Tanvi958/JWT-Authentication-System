package com.tanvi.auth.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.tanvi.auth.domain.Permission.*;

/** Each role is a set of permissions; higher roles include everything below them. */
public enum Role {
    USER(EnumSet.of(PROFILE_READ, PROFILE_WRITE)),
    MODERATOR(EnumSet.of(PROFILE_READ, PROFILE_WRITE, CONTENT_MODERATE, USERS_READ)),
    ADMIN(EnumSet.allOf(Permission.class));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> permissions() {
        return permissions;
    }

    public List<String> permissionNames() {
        return permissions.stream().map(Permission::authority).sorted().toList();
    }

    /** {@code ROLE_ADMIN} plus one authority per permission, e.g. {@code users:write}. */
    public List<GrantedAuthority> authorities() {
        List<GrantedAuthority> list = new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_" + name()));
        permissions.forEach(p -> list.add(new SimpleGrantedAuthority(p.authority())));
        return list;
    }
}
