package com.tanvi.auth.web.dto;

import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.SecurityEvent;
import com.tanvi.auth.domain.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;

import java.time.Instant;
import java.util.List;

public final class AccountDtos {

    private AccountDtos() {
    }

    public record UpdateProfileRequest(
            @NotBlank(message = "Full name is required")
            @Size(max = 100, message = "Full name must be at most 100 characters")
            String fullName
    ) {
    }

    public record ChangePasswordRequest(
            @NotBlank(message = "Current password is required") String currentPassword,
            @NotBlank(message = "New password is required") String newPassword
    ) {
    }

    /** A signed-in device. {@code id} is the session id (refresh-token family). */
    public record SessionResponse(
            String id,
            String device,
            String userAgent,
            String ipAddress,
            Instant signedInAt,
            Instant lastRefreshedAt,
            Instant expiresAt,
            boolean current
    ) {
    }

    public record EventResponse(
            Long id,
            Instant occurredAt,
            SecurityEvent.Type type,
            Long userId,
            String username,
            String actor,
            String ipAddress,
            String detail
    ) {
        public static EventResponse from(SecurityEvent e) {
            return new EventResponse(e.getId(), e.getOccurredAt(), e.getType(), e.getUserId(), e.getUsername(),
                    e.getActor(), e.getIpAddress(), e.getDetail());
        }
    }

    // ---------------------------------------------------------------- admin

    public record AdminUserResponse(
            Long id,
            String username,
            String email,
            String fullName,
            Role role,
            boolean enabled,
            boolean locked,
            Instant lockedUntil,
            int failedAttempts,
            long activeSessions,
            Instant createdAt,
            Instant lastLoginAt
    ) {
        public static AdminUserResponse from(User u, long activeSessions, Instant now) {
            return new AdminUserResponse(u.getId(), u.getUsername(), u.getEmail(), u.getFullName(), u.getRole(),
                    u.isEnabled(), u.isLocked(now), u.isLocked(now) ? u.getLockedUntil() : null,
                    u.getFailedAttempts(), activeSessions, u.getCreatedAt(), u.getLastLoginAt());
        }
    }

    public record ChangeRoleRequest(@NotNull(message = "Role is required") Role role) {
    }

    public record ChangeStatusRequest(@NotNull(message = "enabled is required") Boolean enabled) {
    }

    public record PageResponse<T>(List<T> content, int page, int size, long totalElements, int totalPages) {
        public static <T> PageResponse<T> from(Page<T> p) {
            return new PageResponse<>(p.getContent(), p.getNumber(), p.getSize(), p.getTotalElements(), p.getTotalPages());
        }
    }
}
