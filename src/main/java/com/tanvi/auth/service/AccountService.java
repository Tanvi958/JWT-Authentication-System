package com.tanvi.auth.service;

import com.tanvi.auth.domain.RefreshToken.RevokeReason;
import com.tanvi.auth.domain.SecurityEvent.Type;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.RefreshTokenRepository;
import com.tanvi.auth.repository.UserRepository;
import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.security.PasswordPolicy;
import com.tanvi.auth.web.dto.AccountDtos.ChangePasswordRequest;
import com.tanvi.auth.web.dto.AccountDtos.EventResponse;
import com.tanvi.auth.web.dto.AccountDtos.SessionResponse;
import com.tanvi.auth.web.dto.AccountDtos.UpdateProfileRequest;
import com.tanvi.auth.web.dto.UserResponse;
import com.tanvi.auth.web.error.ApiException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/** What a signed-in user can do with their own account. */
@Service
public class AccountService {

    private final UserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final SessionService sessions;
    private final AuditService audit;

    public AccountService(UserRepository users, RefreshTokenRepository refreshTokens, PasswordEncoder passwordEncoder,
                          PasswordPolicy passwordPolicy, SessionService sessions, AuditService audit) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.sessions = sessions;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public UserResponse me(AuthenticatedUser me) {
        return UserResponse.from(load(me));
    }

    @Transactional
    public UserResponse updateProfile(AuthenticatedUser me, UpdateProfileRequest req, ClientInfo client) {
        User user = load(me);
        user.setFullName(req.fullName().trim());
        audit.record(Type.PROFILE_UPDATED, user, client, null);
        return UserResponse.from(user);
    }

    /**
     * Changes the password and signs the user out everywhere, including this device: whoever might have known
     * the old password loses access immediately.
     */
    @Transactional
    public void changePassword(AuthenticatedUser me, ChangePasswordRequest req, ClientInfo client) {
        User user = load(me);
        if (!passwordEncoder.matches(req.currentPassword(), user.getPasswordHash())) {
            throw ApiException.badRequest("wrong_current_password", "Your current password is incorrect");
        }
        if (passwordEncoder.matches(req.newPassword(), user.getPasswordHash())) {
            throw ApiException.badRequest("password_reused", "Choose a password different from your current one");
        }
        List<String> problems = passwordPolicy.violations(req.newPassword(), user.getUsername(), user.getEmail());
        if (!problems.isEmpty()) {
            throw ApiException.badRequest("weak_password", passwordPolicy.describe(problems));
        }
        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        user.setPasswordChangedAt(Instant.now());
        user.bumpTokenVersion();
        sessions.endAllSessions(user.getId(), RevokeReason.PASSWORD_CHANGED);
        audit.record(Type.PASSWORD_CHANGED, user, client, "all sessions signed out");
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> sessions(AuthenticatedUser me) {
        return sessions.activeSessions(me.id(), me.sessionId());
    }

    /** Signs out one of the user's own devices. */
    @Transactional
    public void revokeSession(AuthenticatedUser me, String sessionId, ClientInfo client) {
        boolean mine = refreshTokens.findActiveByUser(me.id(), Instant.now()).stream()
                .anyMatch(t -> t.getFamilyId().equals(sessionId));
        if (!mine) {
            throw ApiException.notFound("No active session with that id");
        }
        sessions.endSession(sessionId, RevokeReason.SESSION_REVOKED);
        audit.record(Type.SESSION_REVOKED, load(me), client, "session " + sessionId.substring(0, Math.min(8, sessionId.length())));
    }

    @Transactional(readOnly = true)
    public List<EventResponse> events(AuthenticatedUser me) {
        return audit.forUser(me.id());
    }

    private User load(AuthenticatedUser me) {
        return users.findById(me.id()).orElseThrow(() -> ApiException.notFound("Account not found"));
    }
}
