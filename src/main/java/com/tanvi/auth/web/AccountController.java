package com.tanvi.auth.web;

import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.service.AccountService;
import com.tanvi.auth.web.dto.AccountDtos.ChangePasswordRequest;
import com.tanvi.auth.web.dto.AccountDtos.EventResponse;
import com.tanvi.auth.web.dto.AccountDtos.SessionResponse;
import com.tanvi.auth.web.dto.AccountDtos.UpdateProfileRequest;
import com.tanvi.auth.web.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** The signed-in user's own account. */
@RestController
@RequestMapping("/api/account")
@Tag(name = "My account")
public class AccountController {

    private final AccountService accountService;
    private final RefreshCookie refreshCookie;

    public AccountController(AccountService accountService, RefreshCookie refreshCookie) {
        this.accountService = accountService;
        this.refreshCookie = refreshCookie;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('profile:read')")
    public UserResponse me(@AuthenticationPrincipal AuthenticatedUser me) {
        return accountService.me(me);
    }

    @PutMapping
    @PreAuthorize("hasAuthority('profile:write')")
    public UserResponse updateProfile(@AuthenticationPrincipal AuthenticatedUser me,
                                      @Valid @RequestBody UpdateProfileRequest request, HttpServletRequest http) {
        return accountService.updateProfile(me, request, ClientInfo.from(http));
    }

    @PutMapping("/password")
    @PreAuthorize("hasAuthority('profile:write')")
    @Operation(summary = "Change password; signs out every session, including this one")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal AuthenticatedUser me,
                                               @Valid @RequestBody ChangePasswordRequest request,
                                               HttpServletRequest http, HttpServletResponse response) {
        accountService.changePassword(me, request, ClientInfo.from(http));
        refreshCookie.clear(response);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    @PreAuthorize("hasAuthority('profile:read')")
    @Operation(summary = "Devices where this account is signed in")
    public List<SessionResponse> sessions(@AuthenticationPrincipal AuthenticatedUser me) {
        return accountService.sessions(me);
    }

    @DeleteMapping("/sessions/{sessionId}")
    @PreAuthorize("hasAuthority('profile:write')")
    @Operation(summary = "Sign out one device")
    public ResponseEntity<Void> revokeSession(@AuthenticationPrincipal AuthenticatedUser me,
                                              @PathVariable String sessionId, HttpServletRequest http) {
        accountService.revokeSession(me, sessionId, ClientInfo.from(http));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/events")
    @PreAuthorize("hasAuthority('profile:read')")
    @Operation(summary = "Recent security activity on this account")
    public List<EventResponse> events(@AuthenticationPrincipal AuthenticatedUser me) {
        return accountService.events(me);
    }
}
