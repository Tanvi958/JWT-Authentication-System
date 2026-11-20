package com.tanvi.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

/** Every tunable security setting, bound from {@code app.*} in application.properties. */
@ConfigurationProperties(prefix = "app")
public record AppProperties(Jwt jwt, Refresh refresh, Lockout lockout, RateLimit rateLimit, Demo demo, Cors cors) {

    /** {@code secret} signs access tokens with HS256 and must be at least 32 bytes. */
    public record Jwt(String secret, String issuer, Duration accessTokenTtl) {
    }

    public record Refresh(Duration tokenTtl, String cookieName, boolean cookieSecure) {
    }

    /** After {@code maxAttempts} wrong passwords in a row the account is locked for {@code duration}. */
    public record Lockout(int maxAttempts, Duration duration) {
    }

    /** Requests per minute per client IP to the login and register endpoints. */
    public record RateLimit(int authRequestsPerMinute) {
    }

    public record Demo(boolean seedUsers) {
    }

    public record Cors(List<String> allowedOrigins) {
    }
}
