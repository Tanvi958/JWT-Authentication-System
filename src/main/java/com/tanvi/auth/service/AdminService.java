package com.tanvi.auth.service;

import com.tanvi.auth.domain.RefreshToken.RevokeReason;
import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.SecurityEvent;
import com.tanvi.auth.domain.SecurityEvent.Type;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.UserRepository;
import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.web.dto.AccountDtos.AdminUserResponse;
import com.tanvi.auth.web.dto.AccountDtos.EventResponse;
import com.tanvi.auth.web.dto.AccountDtos.PageResponse;
import com.tanvi.auth.web.error.ApiException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/** User administration. Permission checks are on {@code AdminController}; business rules are here. */
@Service
public class AdminService {

    private final UserRepository users;
    private final SessionService sessions;
    private final AuditService audit;

    public AdminService(UserRepository users, SessionService sessions, AuditService audit) {
        this.users = users;
        this.sessions = sessions;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public PageResponse<AdminUserResponse> listUsers(String q, int page, int size) {
        Instant now = Instant.now();
        String query = q == null ? "" : q.trim().toLowerCase();
        var result = users.search(query, PageRequest.of(Math.max(0, page), Math.clamp(size, 1, 100), Sort.by("id")));
        return PageResponse.from(result.map(u -> AdminUserResponse.from(u, sessions.countActive(u.getId()), now)));
    }

    /**
     * Changing a role bumps the user's token version, so tokens carrying the old role stop working; the
     * user's app refreshes and receives a token with the new role.
     */
    @Transactional
    public AdminUserResponse changeRole(AuthenticatedUser actor, Long id, Role role, ClientInfo client) {
        User user = load(id);
        if (user.getId().equals(actor.id())) {
            throw ApiException.badRequest("cannot_change_own_role", "You can't change your own role");
        }
        if (user.getRole() == role) {
            return toResponse(user);
        }
        guardLastAdmin(user);
        Role old = user.getRole();
        user.setRole(role);
        user.bumpTokenVersion();
        audit.record(Type.ROLE_CHANGED, user.getId(), user.getUsername(), actor.username(), client, old + " → " + role);
        return toResponse(user);
    }

    /** Disabling signs the user out everywhere and blocks new logins. */
    @Transactional
    public AdminUserResponse setEnabled(AuthenticatedUser actor, Long id, boolean enabled, ClientInfo client) {
        User user = load(id);
        if (user.getId().equals(actor.id())) {
            throw ApiException.badRequest("cannot_disable_self", "You can't disable your own account");
        }
        if (user.isEnabled() == enabled) {
            return toResponse(user);
        }
        if (!enabled) {
            guardLastAdmin(user);
            user.bumpTokenVersion();
        }
        user.setEnabled(enabled);
        if (!enabled) {
            sessions.endAllSessions(user.getId(), RevokeReason.ADMIN_ACTION);
        }
        audit.record(enabled ? Type.ACCOUNT_ENABLED : Type.ACCOUNT_DISABLED, user.getId(), user.getUsername(),
                actor.username(), client, null);
        return toResponse(user);
    }

    @Transactional
    public AdminUserResponse unlock(AuthenticatedUser actor, Long id, ClientInfo client) {
        User user = load(id);
        user.setLockedUntil(null);
        user.setFailedAttempts(0);
        audit.record(Type.ACCOUNT_UNLOCKED, user.getId(), user.getUsername(), actor.username(), client, null);
        return toResponse(user);
    }

    @Transactional
    public AdminUserResponse revokeSessions(AuthenticatedUser actor, Long id, ClientInfo client) {
        User user = load(id);
        user.bumpTokenVersion();
        sessions.endAllSessions(user.getId(), RevokeReason.ADMIN_ACTION);
        audit.record(Type.SESSIONS_REVOKED_BY_ADMIN, user.getId(), user.getUsername(), actor.username(), client, null);
        return toResponse(user);
    }

    @Transactional(readOnly = true)
    public PageResponse<EventResponse> auditLog(SecurityEvent.Type type, int page, int size) {
        return audit.list(type, page, size);
    }

    private void guardLastAdmin(User user) {
        if (user.getRole() == Role.ADMIN && user.isEnabled() && users.countByRoleAndEnabledTrue(Role.ADMIN) <= 1) {
            throw ApiException.conflict("last_admin", "There must always be at least one active admin");
        }
    }

    private User load(Long id) {
        return users.findById(id).orElseThrow(() -> ApiException.notFound("User not found"));
    }

    private AdminUserResponse toResponse(User user) {
        return AdminUserResponse.from(user, sessions.countActive(user.getId()), Instant.now());
    }
}
