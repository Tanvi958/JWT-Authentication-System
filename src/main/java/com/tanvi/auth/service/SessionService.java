package com.tanvi.auth.service;

import com.tanvi.auth.config.AppProperties;
import com.tanvi.auth.domain.RefreshToken;
import com.tanvi.auth.domain.RefreshToken.RevokeReason;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.RefreshTokenRepository;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.web.dto.AccountDtos.SessionResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh tokens and the sessions they make up.
 *
 * <p>A refresh token is 256 random bits, given to the client once and stored only as a SHA-256 hash, so a
 * leaked database can't be used to sign in. Every token of one sign-in shares a family id: that is the
 * session. Refreshing rotates the token (the old one is revoked, a new one is issued in the same family).
 */
@Service
public class SessionService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenRepository tokens;
    private final AppProperties props;

    public SessionService(RefreshTokenRepository tokens, AppProperties props) {
        this.tokens = tokens;
        this.props = props;
    }

    /** The raw token for the client, and its stored row. */
    public record IssuedRefreshToken(String rawValue, RefreshToken token) {
    }

    @Transactional
    public IssuedRefreshToken startSession(User user, ClientInfo client) {
        Instant now = Instant.now();
        return issue(user, UUID.randomUUID().toString(), now, now, client);
    }

    /** Revokes {@code current} as rotated and issues its successor in the same session. */
    @Transactional
    public IssuedRefreshToken rotate(RefreshToken current, ClientInfo client) {
        Instant now = Instant.now();
        IssuedRefreshToken next = issue(current.getUser(), current.getFamilyId(), current.getSessionStartedAt(), now, client);
        current.revoke(now, RevokeReason.ROTATED);
        current.setReplacedById(next.token().getId());
        tokens.save(current);
        return next;
    }

    private IssuedRefreshToken issue(User user, String familyId, Instant sessionStartedAt, Instant now, ClientInfo client) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        RefreshToken token = tokens.save(new RefreshToken(user, hash(raw), familyId, sessionStartedAt, now,
                now.plus(props.refresh().tokenTtl()), client.userAgent(), client.ip()));
        return new IssuedRefreshToken(raw, token);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> find(String rawValue) {
        if (rawValue == null || rawValue.isBlank() || rawValue.length() > 100) return Optional.empty();
        return tokens.findByTokenHash(hash(rawValue));
    }

    @Transactional
    public void endSession(String familyId, RevokeReason reason) {
        tokens.revokeFamily(familyId, reason, Instant.now());
    }

    @Transactional
    public void endAllSessions(Long userId, RevokeReason reason) {
        tokens.revokeAllForUser(userId, reason, Instant.now());
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> activeSessions(Long userId, String currentSessionId) {
        return tokens.findActiveByUser(userId, Instant.now()).stream()
                .map(t -> new SessionResponse(t.getFamilyId(), ClientInfo.describe(t.getUserAgent()), t.getUserAgent(),
                        t.getIpAddress(), t.getSessionStartedAt(), t.getCreatedAt(), t.getExpiresAt(),
                        t.getFamilyId().equals(currentSessionId)))
                .toList();
    }

    @Transactional(readOnly = true)
    public long countActive(Long userId) {
        return tokens.countActiveByUser(userId, Instant.now());
    }

    static String hash(String raw) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
