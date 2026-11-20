package com.tanvi.auth.security;

import com.tanvi.auth.web.error.ErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window rate limit on the login and register endpoints, per client IP, to slow down password
 * guessing and sign-up spam. Answers 429 with {@code Retry-After} when the limit is reached.
 *
 * <p>The counters live in memory, which is right for a single instance. Several instances would share them
 * through Redis or a gateway instead.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Set<String> LIMITED_PATHS = Set.of("/api/auth/login", "/api/auth/register");
    private static final long WINDOW_MS = 60_000;

    private final int limit;
    private final Clock clock;
    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    public RateLimitFilter(int requestsPerMinute, Clock clock) {
        this.limit = requestsPerMinute;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod()) || !LIMITED_PATHS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long now = clock.millis();
        String key = request.getRemoteAddr() + "|" + request.getRequestURI();
        Deque<Long> window = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        long retryAfterMs;
        synchronized (window) {
            while (!window.isEmpty() && now - window.peekFirst() >= WINDOW_MS) {
                window.pollFirst();
            }
            if (window.size() < limit) {
                window.addLast(now);
                retryAfterMs = 0;
            } else {
                retryAfterMs = WINDOW_MS - (now - window.peekFirst());
            }
        }
        if (retryAfterMs > 0) {
            long seconds = Math.max(1, (retryAfterMs + 999) / 1000);
            response.setHeader("Retry-After", String.valueOf(seconds));
            ErrorResponse.write(response, 429, "Too Many Requests", "rate_limited",
                    "Too many attempts. Try again in " + seconds + " seconds.", request.getRequestURI());
            return;
        }
        if (hits.size() > 10_000) {
            hits.entrySet().removeIf(e -> e.getValue().isEmpty() || now - e.getValue().peekLast() >= WINDOW_MS);
        }
        chain.doFilter(request, response);
    }
}
