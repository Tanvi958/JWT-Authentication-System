package com.tanvi.auth.security;

import com.tanvi.auth.domain.Role;

/**
 * The signed-in caller, built from a verified access token. Available in controllers via
 * {@code @AuthenticationPrincipal}.
 */
public record AuthenticatedUser(Long id, String username, Role role, String sessionId, String tokenId) {

    @Override
    public String toString() {
        return username;
    }
}
