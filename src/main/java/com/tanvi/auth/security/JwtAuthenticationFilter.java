package com.tanvi.auth.security;

import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.RefreshTokenRepository;
import com.tanvi.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

/**
 * Authenticates requests that carry {@code Authorization: Bearer <access token>}.
 *
 * <p>A valid signature is not enough. The token is also rejected when:
 * <ul>
 *   <li>the account was disabled or is locked,</li>
 *   <li>its {@code ver} claim is older than the user's token version (password or role changed,
 *       "log out everywhere"), or</li>
 *   <li>its session ({@code sid}) was logged out or revoked.</li>
 * </ul>
 * That makes logout and revocation take effect immediately instead of when the token expires.
 * When a token is rejected, the reason is left as a request attribute for {@link RestAuthenticationEntryPoint}.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String ERROR_ATTRIBUTE = "auth.error";

    private final JwtService jwtService;
    private final UserRepository users;
    private final RefreshTokenRepository refreshTokens;

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository users, RefreshTokenRepository refreshTokens) {
        this.jwtService = jwtService;
        this.users = users;
        this.refreshTokens = refreshTokens;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            authenticate(request, header.substring(7).trim());
        }
        chain.doFilter(request, response);
    }

    private void authenticate(HttpServletRequest request, String token) {
        Claims claims;
        try {
            claims = jwtService.parse(token);
        } catch (ExpiredJwtException e) {
            reject(request, AuthError.TOKEN_EXPIRED);
            return;
        } catch (JwtException | IllegalArgumentException e) {
            reject(request, AuthError.TOKEN_INVALID);
            return;
        }

        Optional<User> found = parseId(claims.getSubject()).flatMap(users::findById);
        if (found.isEmpty()) {
            reject(request, AuthError.TOKEN_INVALID);
            return;
        }
        User user = found.get();
        Instant now = Instant.now();
        Integer version = claims.get("ver", Integer.class);
        String sessionId = claims.get("sid", String.class);

        if (!user.isEnabled()) {
            reject(request, AuthError.ACCOUNT_DISABLED);
        } else if (user.isLocked(now)) {
            reject(request, AuthError.ACCOUNT_LOCKED);
        } else if (version == null || version != user.getTokenVersion()) {
            reject(request, AuthError.TOKEN_STALE);
        } else if (sessionId == null || !refreshTokens.isFamilyActive(sessionId, now)) {
            reject(request, AuthError.SESSION_ENDED);
        } else {
            // Authorities come from the user's current role in the database, not from the token.
            AuthenticatedUser principal = new AuthenticatedUser(user.getId(), user.getUsername(), user.getRole(),
                    sessionId, claims.getId());
            var auth = new UsernamePasswordAuthenticationToken(principal, null, user.getRole().authorities());
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }

    private static Optional<Long> parseId(String subject) {
        try {
            return Optional.of(Long.parseLong(subject));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static void reject(HttpServletRequest request, AuthError error) {
        request.setAttribute(ERROR_ATTRIBUTE, error);
    }

    /** Why a bearer token was not accepted. {@code code} is returned to the client. */
    public enum AuthError {
        TOKEN_EXPIRED("token_expired", "The access token has expired"),
        TOKEN_INVALID("token_invalid", "The access token is invalid"),
        TOKEN_STALE("token_stale", "The access token is out of date; refresh it"),
        SESSION_ENDED("session_ended", "This session has been signed out"),
        ACCOUNT_DISABLED("account_disabled", "This account has been disabled"),
        ACCOUNT_LOCKED("account_locked", "This account is temporarily locked");

        public final String code;
        public final String message;

        AuthError(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
