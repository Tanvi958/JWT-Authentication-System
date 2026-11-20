package com.tanvi.auth.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class AuthDtos {

    private AuthDtos() {
    }

    public record RegisterRequest(
            @NotBlank(message = "Username is required")
            @Pattern(regexp = "^[a-zA-Z0-9._-]{3,30}$",
                    message = "Username must be 3-30 letters, digits, dots, dashes or underscores")
            String username,

            @NotBlank(message = "Email is required")
            @Email(message = "Email must be a valid address")
            @Size(max = 120, message = "Email must be at most 120 characters")
            String email,

            @NotBlank(message = "Full name is required")
            @Size(max = 100, message = "Full name must be at most 100 characters")
            String fullName,

            @NotBlank(message = "Password is required")
            String password
    ) {
    }

    /** {@code login} is a username or an e-mail address. */
    public record LoginRequest(
            @NotBlank(message = "Username or email is required") String login,
            @NotBlank(message = "Password is required") String password
    ) {
    }

    /**
     * Returned by login and refresh. The refresh token is not in the body: it is set as an HttpOnly cookie,
     * out of reach of JavaScript.
     */
    public record TokenResponse(
            String accessToken,
            String tokenType,
            long expiresIn,
            Instant expiresAt,
            UserResponse user
    ) {
    }
}
