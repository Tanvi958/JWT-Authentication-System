package com.tanvi.auth.web;

import com.tanvi.auth.domain.SecurityEvent;
import com.tanvi.auth.security.AuthenticatedUser;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.service.AdminService;
import com.tanvi.auth.web.dto.AccountDtos.AdminUserResponse;
import com.tanvi.auth.web.dto.AccountDtos.ChangeRoleRequest;
import com.tanvi.auth.web.dto.AccountDtos.ChangeStatusRequest;
import com.tanvi.auth.web.dto.AccountDtos.EventResponse;
import com.tanvi.auth.web.dto.AccountDtos.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * User administration. Each endpoint asks for a permission rather than a role, so roles can be
 * re-shaped without touching the code: moderators can view users, only admins can change them.
 */
@RestController
@RequestMapping("/api/admin")
@Tag(name = "Administration")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('users:read')")
    @Operation(summary = "Search users (moderators and admins)")
    public PageResponse<AdminUserResponse> users(@RequestParam(required = false) String q,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "20") int size) {
        return adminService.listUsers(q, page, size);
    }

    @PutMapping("/users/{id}/role")
    @PreAuthorize("hasAuthority('users:write')")
    @Operation(summary = "Change a user's role (forces their tokens to refresh)")
    public AdminUserResponse changeRole(@AuthenticationPrincipal AuthenticatedUser me, @PathVariable Long id,
                                        @Valid @RequestBody ChangeRoleRequest request, HttpServletRequest http) {
        return adminService.changeRole(me, id, request.role(), ClientInfo.from(http));
    }

    @PutMapping("/users/{id}/status")
    @PreAuthorize("hasAuthority('users:write')")
    @Operation(summary = "Enable or disable an account (disabling signs it out everywhere)")
    public AdminUserResponse changeStatus(@AuthenticationPrincipal AuthenticatedUser me, @PathVariable Long id,
                                          @Valid @RequestBody ChangeStatusRequest request, HttpServletRequest http) {
        return adminService.setEnabled(me, id, request.enabled(), ClientInfo.from(http));
    }

    @PostMapping("/users/{id}/unlock")
    @PreAuthorize("hasAuthority('users:write')")
    @Operation(summary = "Clear a lockout after too many failed logins")
    public AdminUserResponse unlock(@AuthenticationPrincipal AuthenticatedUser me, @PathVariable Long id,
                                    HttpServletRequest http) {
        return adminService.unlock(me, id, ClientInfo.from(http));
    }

    @DeleteMapping("/users/{id}/sessions")
    @PreAuthorize("hasAuthority('users:write')")
    @Operation(summary = "Sign a user out on every device")
    public AdminUserResponse revokeSessions(@AuthenticationPrincipal AuthenticatedUser me, @PathVariable Long id,
                                            HttpServletRequest http) {
        return adminService.revokeSessions(me, id, ClientInfo.from(http));
    }

    @GetMapping("/audit")
    @PreAuthorize("hasAuthority('audit:read')")
    @Operation(summary = "Security audit log, newest first")
    public PageResponse<EventResponse> audit(@RequestParam(required = false) SecurityEvent.Type type,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(defaultValue = "25") int size) {
        return adminService.auditLog(type, page, size);
    }
}
