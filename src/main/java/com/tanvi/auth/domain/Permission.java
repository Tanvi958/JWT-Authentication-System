package com.tanvi.auth.domain;

/** Fine-grained authorities. Roles are bundles of these; endpoints check permissions, not role names. */
public enum Permission {
    PROFILE_READ("profile:read"),
    PROFILE_WRITE("profile:write"),
    CONTENT_MODERATE("content:moderate"),
    USERS_READ("users:read"),
    USERS_WRITE("users:write"),
    AUDIT_READ("audit:read");

    private final String authority;

    Permission(String authority) {
        this.authority = authority;
    }

    public String authority() {
        return authority;
    }
}
