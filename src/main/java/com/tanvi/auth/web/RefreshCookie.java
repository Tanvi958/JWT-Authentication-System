package com.tanvi.auth.web;

import com.tanvi.auth.config.AppProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Arrays;

/**
 * The refresh-token cookie: {@code HttpOnly} (JavaScript can't read it, so XSS can't steal it),
 * {@code SameSite=Strict} (other sites can't make the browser send it) and {@code Path=/api/auth}
 * (it is only sent to the auth endpoints, never with ordinary API calls).
 */
@Component
public class RefreshCookie {

    static final String PATH = "/api/auth";

    private final AppProperties props;

    public RefreshCookie(AppProperties props) {
        this.props = props;
    }

    public void set(HttpServletResponse response, String token) {
        write(response, token, props.refresh().tokenTtl());
    }

    public void clear(HttpServletResponse response) {
        write(response, "", Duration.ZERO);
    }

    public String read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        return Arrays.stream(cookies)
                .filter(c -> props.refresh().cookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst().orElse(null);
    }

    private void write(HttpServletResponse response, String value, Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(props.refresh().cookieName(), value)
                .httpOnly(true)
                .secure(props.refresh().cookieSecure())
                .sameSite("Strict")
                .path(PATH)
                .maxAge(maxAge)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
