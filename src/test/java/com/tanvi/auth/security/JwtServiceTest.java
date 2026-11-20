package com.tanvi.auth.security;

import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-0123456789-abcdefghijklmnop";
    private static final Instant NOW = Instant.parse("2026-11-20T10:00:00Z");

    private final User user = user();

    private static User user() {
        User u = new User("asha", "asha@example.com", "Asha", "{noop}x", Role.MODERATOR);
        ReflectionTestUtils.setField(u, "id", 42L);
        return u;
    }

    private static JwtService service(Instant now) {
        return new JwtService(SECRET, "jwt-auth-system", Duration.ofMinutes(15), Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void issuesATokenWithTheExpectedClaims() {
        JwtService.AccessToken token = service(NOW).issue(user, "session-1");
        Claims claims = service(NOW).parse(token.value());

        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getIssuer()).isEqualTo("jwt-auth-system");
        assertThat(claims.getId()).isEqualTo(token.id());
        assertThat(claims.get("username", String.class)).isEqualTo("asha");
        assertThat(claims.get("role", String.class)).isEqualTo("MODERATOR");
        assertThat(claims.get("perms", List.class)).contains("users:read", "content:moderate").doesNotContain("users:write");
        assertThat(claims.get("sid", String.class)).isEqualTo("session-1");
        assertThat(claims.get("ver", Integer.class)).isZero();
        assertThat(claims.getExpiration().toInstant()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(token.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
    }

    @Test
    void usesHs256AndNeverPutsThePasswordHashInTheToken() {
        String token = service(NOW).issue(user, "s").value();
        String header = new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        assertThat(header).contains("\"alg\":\"HS256\"");
        assertThat(payload).doesNotContain("noop").doesNotContain("password");
    }

    @Test
    void rejectsExpiredTokens() {
        String token = service(NOW).issue(user, "s").value();
        assertThatCode(() -> service(NOW.plus(Duration.ofMinutes(15))).parse(token)).doesNotThrowAnyException(); // within skew
        assertThatThrownBy(() -> service(NOW.plus(Duration.ofMinutes(16))).parse(token))
                .isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void rejectsTamperedTokens() {
        String token = service(NOW).issue(user, "s").value();
        String[] parts = token.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1])).replace("MODERATOR", "ADMIN");
        String forged = parts[0] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes()) + "." + parts[2];
        assertThatThrownBy(() -> service(NOW).parse(forged)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokensSignedWithAnotherKeyOrIssuer() {
        JwtService other = new JwtService("a-completely-different-secret-0123456789xyz", "jwt-auth-system",
                Duration.ofMinutes(15), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> service(NOW).parse(other.issue(user, "s").value())).isInstanceOf(JwtException.class);

        JwtService otherIssuer = new JwtService(SECRET, "someone-else", Duration.ofMinutes(15), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> service(NOW).parse(otherIssuer.issue(user, "s").value())).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsUnsignedTokens() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"sub\":\"42\",\"iss\":\"jwt-auth-system\",\"role\":\"ADMIN\"}".getBytes());
        assertThatThrownBy(() -> service(NOW).parse(header + "." + payload + ".")).isInstanceOf(JwtException.class);
    }

    @Test
    void refusesShortSecrets() {
        assertThatThrownBy(() -> new JwtService("too-short", "i", Duration.ofMinutes(1), Clock.systemUTC()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 32 bytes");
    }
}
