package com.tanvi.auth.web;

import com.tanvi.auth.security.AuthenticatedUser;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Four endpoints with increasing requirements, to see access control at work. */
@RestController
@RequestMapping("/api/demo")
@Tag(name = "Access demo")
public class DemoController {

    @GetMapping("/public")
    public Map<String, String> open() {
        return Map.of("access", "public", "message", "Anyone can read this, signed in or not.");
    }

    @GetMapping("/user")
    @PreAuthorize("isAuthenticated()")
    public Map<String, String> user(@AuthenticationPrincipal AuthenticatedUser me) {
        return Map.of("access", "any signed-in user", "message", "Hello " + me.username() + ", your token is valid.");
    }

    @GetMapping("/moderator")
    @PreAuthorize("hasAuthority('content:moderate')")
    public Map<String, String> moderator(@AuthenticationPrincipal AuthenticatedUser me) {
        return Map.of("access", "permission content:moderate", "message", "Moderation tools unlocked for " + me.username() + ".");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> admin(@AuthenticationPrincipal AuthenticatedUser me) {
        return Map.of("access", "role ADMIN", "message", "Welcome to the admin area, " + me.username() + ".");
    }
}
