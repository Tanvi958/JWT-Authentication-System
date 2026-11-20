package com.tanvi.auth.security;

import com.tanvi.auth.config.AppProperties;
import com.tanvi.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Issues and verifies access tokens: short-lived JWTs signed with HMAC-SHA256.
 *
 * <p>Claims: {@code sub} (user id), {@code username}, {@code role}, {@code perms}, {@code sid} (session id,
 * i.e. the refresh-token family), {@code ver} (the user's token version), plus {@code jti}, {@code iss},
 * {@code iat} and {@code exp}.
 */
@Service
public class JwtService {

    private final SecretKey key;
    private final String issuer;
    private final Duration ttl;
    private final Clock clock;

    @Autowired
    public JwtService(AppProperties props) {
        this(props.jwt().secret(), props.jwt().issuer(), props.jwt().accessTokenTtl(), Clock.systemUTC());
    }

    JwtService(String secret, String issuer, Duration ttl, Clock clock) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret (JWT_SECRET) must be at least 32 bytes for HS256");
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.issuer = issuer;
        this.ttl = ttl;
        this.clock = clock;
    }

    public record AccessToken(String value, String id, Instant expiresAt) {
    }

    public AccessToken issue(User user, String sessionId) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(ttl);
        String jti = UUID.randomUUID().toString();
        String token = Jwts.builder()
                .id(jti)
                .issuer(issuer)
                .subject(String.valueOf(user.getId()))
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim("username", user.getUsername())
                .claim("role", user.getRole().name())
                .claim("perms", user.getRole().permissionNames())
                .claim("sid", sessionId)
                .claim("ver", user.getTokenVersion())
                .signWith(key, Jwts.SIG.HS256)
                .compact();
        return new AccessToken(token, jti, expiresAt);
    }

    /**
     * Verifies the signature, issuer and expiry, and returns the claims.
     *
     * @throws io.jsonwebtoken.ExpiredJwtException if the token has expired
     * @throws JwtException                        if it is malformed, tampered with or from another issuer
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(issuer)
                .clock(() -> Date.from(clock.instant()))
                .clockSkewSeconds(5)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Duration ttl() {
        return ttl;
    }
}
