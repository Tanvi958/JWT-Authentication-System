package com.tanvi.auth.security;

import com.tanvi.auth.web.error.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * Answers unauthenticated requests to protected endpoints with 401 and a precise {@code code}, so a client
 * knows whether to refresh ({@code token_expired}, {@code token_stale}) or send the user to sign in.
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
            throws IOException {
        Object error = request.getAttribute(JwtAuthenticationFilter.ERROR_ATTRIBUTE);
        String code = "unauthenticated";
        String message = "Sign in to access this resource";
        if (error instanceof JwtAuthenticationFilter.AuthError e) {
            code = e.code;
            message = e.message;
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"" + code + "\"");
        } else {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        ErrorResponse.write(response, 401, "Unauthorized", code, message, request.getRequestURI());
    }
}
