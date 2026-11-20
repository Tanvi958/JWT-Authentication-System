package com.tanvi.auth.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

/** One entry in the security audit log. */
@Entity
@Table(name = "security_events")
public class SecurityEvent {

    public enum Type {
        REGISTERED, LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, LOCKED_LOGIN_ATTEMPT,
        LOGOUT, LOGOUT_ALL, TOKEN_REUSE_DETECTED, PASSWORD_CHANGED, PROFILE_UPDATED,
        SESSION_REVOKED, ROLE_CHANGED, ACCOUNT_DISABLED, ACCOUNT_ENABLED, ACCOUNT_UNLOCKED, SESSIONS_REVOKED_BY_ADMIN
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 40)
    private Type type;

    /** The account the event is about (null when a login names an unknown user). */
    @Column(name = "user_id")
    private Long userId;

    /** The account name as typed or stored. */
    @Column(length = 120)
    private String username;

    /** Who caused it, when different from the account (e.g. the admin who changed a role). */
    @Column(length = 30)
    private String actor;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(length = 255)
    private String detail;

    protected SecurityEvent() {
    }

    public SecurityEvent(Type type, Long userId, String username, String actor, String ipAddress, String detail) {
        this.occurredAt = Instant.now();
        this.type = type;
        this.userId = userId;
        this.username = truncate(username, 120);
        this.actor = truncate(actor, 30);
        this.ipAddress = truncate(ipAddress, 45);
        this.detail = truncate(detail, 255);
    }

    private static String truncate(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public Type getType() { return type; }
    public Long getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getActor() { return actor; }
    public String getIpAddress() { return ipAddress; }
    public String getDetail() { return detail; }
}
