package com.tanvi.auth.web;

import com.tanvi.auth.config.AppProperties;
import com.tanvi.auth.config.DemoUserSeeder;
import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.service.AuthService;
import com.tanvi.auth.web.dto.AuthDtos.LoginRequest;
import com.tanvi.auth.web.dto.AuthDtos.RegisterRequest;
import com.tanvi.auth.web.dto.AuthDtos.TokenResponse;
import com.tanvi.auth.web.dto.UserResponse;
import com.tanvi.auth.web.error.ApiException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication")
public class AuthController {

    private final AuthService authService;
    private final RefreshCookie refreshCookie;
    private final AppProperties props;

    public AuthController(AuthService authService, RefreshCookie refreshCookie, AppProperties props) {
        this.authService = authService;
        this.refreshCookie = refreshCookie;
        this.props = props;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create an account (role USER)")
    public UserResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        return authService.register(request, ClientInfo.from(http));
    }

    @PostMapping("/login")
    @Operation(summary = "Sign in with username or email; returns an access token and sets the refresh cookie")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http,
                               HttpServletResponse response) {
        AuthService.AuthResult result = authService.login(request, ClientInfo.from(http));
        refreshCookie.set(response, result.refreshToken());
        return result.body();
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate the refresh cookie and get a new access token")
    public TokenResponse refresh(HttpServletRequest http, HttpServletResponse response) {
        try {
            AuthService.AuthResult result = authService.refresh(refreshCookie.read(http), ClientInfo.from(http));
            refreshCookie.set(response, result.refreshToken());
            return result.body();
        } catch (ApiException e) {
            refreshCookie.clear(response);
            throw e;
        }
    }

    @PostMapping("/logout")
    @Operation(summary = "End this session (identified by the refresh cookie)")
    public ResponseEntity<Void> logout(HttpServletRequest http, HttpServletResponse response) {
        authService.logout(refreshCookie.read(http), ClientInfo.from(http));
        refreshCookie.clear(response);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Sign out on every device")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal AuthenticatedUser me, HttpServletRequest http,
                                          HttpServletResponse response) {
        authService.logoutEverywhere(me, ClientInfo.from(http));
        refreshCookie.clear(response);
        return ResponseEntity.noContent().build();
    }

    /** Lets the sign-in page offer one-click demo accounts, only when they were created. */
    @GetMapping("/demo-accounts")
    @Operation(summary = "Demo accounts, when demo seeding is on")
    public Map<String, Object> demoAccounts() {
        if (!props.demo().seedUsers()) {
            return Map.of("enabled", false, "accounts", List.of());
        }
        return Map.of("enabled", true, "accounts", DemoUserSeeder.ACCOUNTS.stream()
                .map(a -> Map.of("username", a.username(), "password", a.password(), "role", a.role().name()))
                .toList());
    }
}
