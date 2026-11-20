package com.tanvi.auth.service;

import com.tanvi.auth.config.AppProperties;
import com.tanvi.auth.domain.RefreshToken;
import com.tanvi.auth.domain.RefreshToken.RevokeReason;
import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.SecurityEvent.Type;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.UserRepository;
import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.security.JwtService;
import com.tanvi.auth.security.PasswordPolicy;
import com.tanvi.auth.web.dto.AuthDtos.LoginRequest;
import com.tanvi.auth.web.dto.AuthDtos.RegisterRequest;
import com.tanvi.auth.web.dto.AuthDtos.TokenResponse;
import com.tanvi.auth.web.dto.UserResponse;
import com.tanvi.auth.web.error.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

/** Registration, login, token refresh and logout. */
@Service
public class AuthService {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final JwtService jwtService;
    private final SessionService sessions;
    private final AuditService audit;
    private final AppProperties props;
    /** Compared against when the username doesn't exist, so both cases take the same time. */
    private final String dummyHash;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder, PasswordPolicy passwordPolicy,
                       JwtService jwtService, SessionService sessions, AuditService audit, AppProperties props) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.jwtService = jwtService;
        this.sessions = sessions;
        this.audit = audit;
        this.props = props;
        this.dummyHash = passwordEncoder.encode("timing-equaliser-not-a-real-password");
    }

    /** A successful login or refresh: the response body, plus the refresh token for the cookie. */
    public record AuthResult(TokenResponse body, String refreshToken) {
    }

    // ---------------------------------------------------------------- register

    @Transactional
    public UserResponse register(RegisterRequest req, ClientInfo client) {
        String username = req.username().trim().toLowerCase();
        String email = req.email().trim().toLowerCase();
        if (users.existsByUsername(username)) {
            throw ApiException.conflict("username_taken", "That username is already taken");
        }
        if (users.existsByEmail(email)) {
            throw ApiException.conflict("email_taken", "An account with that email already exists");
        }
        List<String> problems = passwordPolicy.violations(req.password(), username, email);
        if (!problems.isEmpty()) {
            throw ApiException.badRequest("weak_password", passwordPolicy.describe(problems));
        }
        User user = users.save(new User(username, email, req.fullName().trim(),
                passwordEncoder.encode(req.password()), Role.USER));
        audit.record(Type.REGISTERED, user, client, null);
        return UserResponse.from(user);
    }

    // ---------------------------------------------------------------- login

    /**
     * Checks the password, counting failures: after {@code app.lockout.max-attempts} wrong passwords in a row
     * the account is locked for {@code app.lockout.duration}. The error never says whether the username
     * exists. {@code noRollbackFor} keeps the failure count and audit entry when the login is refused.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResult login(LoginRequest req, ClientInfo client) {
        String login = req.login().trim().toLowerCase();
        Optional<User> found = login.contains("@") ? users.findByEmail(login) : users.findByUsername(login);
        Instant now = Instant.now();

        if (found.isEmpty()) {
            passwordEncoder.matches(req.password(), dummyHash);
            audit.record(Type.LOGIN_FAILED, null, login, null, client, "unknown account");
            throw invalidCredentials();
        }
        User user = found.get();

        if (user.isLocked(now)) {
            audit.record(Type.LOCKED_LOGIN_ATTEMPT, user, client, null);
            throw locked(user);
        }
        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            int attempts = user.getFailedAttempts() + 1;
            if (attempts >= props.lockout().maxAttempts()) {
                user.setFailedAttempts(0);
                user.setLockedUntil(now.plus(props.lockout().duration()));
                audit.record(Type.ACCOUNT_LOCKED, user, client, attempts + " failed attempts");
                throw locked(user);
            }
            user.setFailedAttempts(attempts);
            audit.record(Type.LOGIN_FAILED, user, client, "wrong password (" + attempts + "/" + props.lockout().maxAttempts() + ")");
            throw invalidCredentials();
        }
        if (!user.isEnabled()) {
            audit.record(Type.LOGIN_FAILED, user, client, "account disabled");
            throw new ApiException(HttpStatus.FORBIDDEN, "account_disabled", "This account has been disabled");
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(now);
        SessionService.IssuedRefreshToken refresh = sessions.startSession(user, client);
        audit.record(Type.LOGIN_SUCCESS, user, client, ClientInfo.describe(client.userAgent()));
        return result(user, refresh);
    }

    // ---------------------------------------------------------------- refresh

    /**
     * Swaps a refresh token for a new access token and a new refresh token (rotation).
     *
     * <p>Reuse detection: a token that was already rotated should never come back. If it does, someone kept
     * a copy, so the whole session is revoked: both the attacker and the real user must sign in again.
     */
    @Transactional(noRollbackFor = ApiException.class)
    public AuthResult refresh(String rawRefreshToken, ClientInfo client) {
        RefreshToken token = sessions.find(rawRefreshToken)
                .orElseThrow(() -> ApiException.unauthorized("refresh_token_invalid", "Sign in again"));
        User user = token.getUser();
        Instant now = Instant.now();

        if (token.getRevokedAt() != null) {
            if (token.getRevokeReason() == RevokeReason.ROTATED) {
                sessions.endSession(token.getFamilyId(), RevokeReason.REUSE_DETECTED);
                audit.record(Type.TOKEN_REUSE_DETECTED, user, client,
                        "session " + token.getFamilyId().substring(0, 8) + " revoked");
                throw ApiException.unauthorized("refresh_token_reused",
                        "This sign-in was ended for your safety. Please sign in again.");
            }
            throw ApiException.unauthorized("session_ended", "This session has been signed out");
        }
        if (!token.getExpiresAt().isAfter(now)) {
            throw ApiException.unauthorized("refresh_token_expired", "Your session has expired. Sign in again.");
        }
        if (!user.isEnabled()) {
            sessions.endAllSessions(user.getId(), RevokeReason.ADMIN_ACTION);
            throw ApiException.unauthorized("account_disabled", "This account has been disabled");
        }
        if (user.isLocked(now)) {
            throw locked(user);
        }
        return result(user, sessions.rotate(token, client));
    }

    // ---------------------------------------------------------------- logout

    /** Ends the session the refresh token belongs to. Its access tokens stop working at once too. */
    @Transactional
    public void logout(String rawRefreshToken, ClientInfo client) {
        sessions.find(rawRefreshToken).filter(t -> t.getRevokedAt() == null).ifPresent(t -> {
            sessions.endSession(t.getFamilyId(), RevokeReason.LOGOUT);
            audit.record(Type.LOGOUT, t.getUser(), client, null);
        });
    }

    /** Signs the user out on every device. */
    @Transactional
    public void logoutEverywhere(AuthenticatedUser me, ClientInfo client) {
        User user = users.findById(me.id()).orElseThrow();
        user.bumpTokenVersion();
        sessions.endAllSessions(user.getId(), RevokeReason.LOGOUT_ALL);
        audit.record(Type.LOGOUT_ALL, user, client, null);
    }

    // ---------------------------------------------------------------- helpers

    private AuthResult result(User user, SessionService.IssuedRefreshToken refresh) {
        JwtService.AccessToken access = jwtService.issue(user, refresh.token().getFamilyId());
        TokenResponse body = new TokenResponse(access.value(), "Bearer", jwtService.ttl().toSeconds(),
                access.expiresAt(), UserResponse.from(user));
        return new AuthResult(body, refresh.rawValue());
    }

    private static ApiException invalidCredentials() {
        return ApiException.unauthorized("invalid_credentials", "Incorrect username/email or password");
    }

    private static ApiException locked(User user) {
        return new ApiException(HttpStatus.LOCKED, "account_locked",
                "Too many failed attempts. The account is locked until " + TIME.format(user.getLockedUntil()) + ".");
    }
}
