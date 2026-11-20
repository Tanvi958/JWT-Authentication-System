package com.tanvi.auth.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

/** One refresh token. Tokens sharing a {@code familyId} belong to the same sign-in (session). */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    public enum RevokeReason { ROTATED, LOGOUT, LOGOUT_ALL, REUSE_DETECTED, PASSWORD_CHANGED, SESSION_REVOKED, ADMIN_ACTION }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "family_id", nullable = false, length = 36)
    private String familyId;

    @Column(name = "session_started_at", nullable = false)
    private Instant sessionStartedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "revoke_reason", length = 30)
    private RevokeReason revokeReason;

    @Column(name = "replaced_by_id")
    private Long replacedById;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    protected RefreshToken() {
    }

    public RefreshToken(User user, String tokenHash, String familyId, Instant sessionStartedAt, Instant createdAt,
                        Instant expiresAt, String userAgent, String ipAddress) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.sessionStartedAt = sessionStartedAt;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
    }

    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }

    public void revoke(Instant now, RevokeReason reason) {
        this.revokedAt = now;
        this.revokeReason = reason;
    }

    public Long getId() { return id; }
    public User getUser() { return user; }
    public String getTokenHash() { return tokenHash; }
    public String getFamilyId() { return familyId; }
    public Instant getSessionStartedAt() { return sessionStartedAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public RevokeReason getRevokeReason() { return revokeReason; }
    public Long getReplacedById() { return replacedById; }
    public void setReplacedById(Long replacedById) { this.replacedById = replacedById; }
    public String getUserAgent() { return userAgent; }
    public String getIpAddress() { return ipAddress; }
}
