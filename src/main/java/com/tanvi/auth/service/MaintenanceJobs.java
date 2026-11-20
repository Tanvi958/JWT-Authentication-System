package com.tanvi.auth.service;

import com.tanvi.auth.repository.RefreshTokenRepository;
import com.tanvi.auth.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/** Nightly clean-up so the token and audit tables don't grow forever. */
@Component
public class MaintenanceJobs {

    private static final Logger log = LoggerFactory.getLogger(MaintenanceJobs.class);

    private final RefreshTokenRepository refreshTokens;
    private final SecurityEventRepository events;

    public MaintenanceJobs(RefreshTokenRepository refreshTokens, SecurityEventRepository events) {
        this.refreshTokens = refreshTokens;
        this.events = events;
    }

    /** Expired refresh tokens are kept for a day (useful for investigating reuse), then deleted. */
    @Scheduled(cron = "${app.cleanup.cron:0 30 3 * * *}")
    @Transactional
    public void purge() {
        int tokens = refreshTokens.deleteExpiredBefore(Instant.now().minus(Duration.ofDays(1)));
        int old = events.deleteOlderThan(Instant.now().minus(Duration.ofDays(90)));
        log.info("Clean-up removed {} expired refresh tokens and {} audit events older than 90 days", tokens, old);
    }
}
