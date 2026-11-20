package com.tanvi.auth.web.dto;

import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.User;

import java.time.Instant;
import java.util.List;

public record UserResponse(
        Long id,
        String username,
        String email,
        String fullName,
        Role role,
        List<String> permissions,
        Instant createdAt,
        Instant lastLoginAt,
        Instant passwordChangedAt
) {
    public static UserResponse from(User u) {
        return new UserResponse(u.getId(), u.getUsername(), u.getEmail(), u.getFullName(), u.getRole(),
                u.getRole().permissionNames(), u.getCreatedAt(), u.getLastLoginAt(), u.getPasswordChangedAt());
    }
}
