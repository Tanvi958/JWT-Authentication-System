package com.tanvi.auth;

import com.jayway.jsonpath.JsonPath;
import com.tanvi.auth.support.ApiTestSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Roles and permissions: who may call what, and how admin actions take effect immediately. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:access_control;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "app.rate-limit.auth-requests-per-minute=10000"})
@AutoConfigureMockMvc
class AccessControlTests extends ApiTestSupport {

    @Test
    @DisplayName("access matrix: public, user, moderator and admin endpoints")
    void accessMatrix() throws Exception {
        Session user = login("user", "Member@123");
        Session mod = login("moderator", "Reviewer@1");
        Session admin = login("admin", "SuperUser@1");

        mvc.perform(get("/api/demo/public")).andExpect(status().isOk());
        mvc.perform(get("/api/demo/user")).andExpect(status().isUnauthorized());

        mvc.perform(get("/api/demo/user").header("Authorization", user.bearer())).andExpect(status().isOk());
        mvc.perform(get("/api/demo/moderator").header("Authorization", user.bearer()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("access_denied"));
        mvc.perform(get("/api/demo/admin").header("Authorization", user.bearer())).andExpect(status().isForbidden());

        mvc.perform(get("/api/demo/moderator").header("Authorization", mod.bearer())).andExpect(status().isOk());
        mvc.perform(get("/api/demo/admin").header("Authorization", mod.bearer())).andExpect(status().isForbidden());

        mvc.perform(get("/api/demo/moderator").header("Authorization", admin.bearer())).andExpect(status().isOk());
        mvc.perform(get("/api/demo/admin").header("Authorization", admin.bearer())).andExpect(status().isOk());
    }

    @Test
    @DisplayName("moderators can view users but not change them; users can do neither")
    void adminEndpointsArePermissionBased() throws Exception {
        Session user = login("user", "Member@123");
        Session mod = login("moderator", "Reviewer@1");

        mvc.perform(get("/api/admin/users").header("Authorization", user.bearer())).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/users").header("Authorization", mod.bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[*].username", hasItems("admin", "moderator", "user")))
                .andExpect(jsonPath("$.content[0].passwordHash").doesNotExist());
        mvc.perform(get("/api/admin/users").param("q", "MOD").header("Authorization", mod.bearer()))
                .andExpect(jsonPath("$.totalElements").value(1));

        mvc.perform(put("/api/admin/users/1/role").header("Authorization", mod.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/audit").header("Authorization", mod.bearer())).andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a role change invalidates old tokens; a refresh picks up the new permissions")
    void roleChangeTakesEffectImmediately() throws Exception {
        Session admin = login("admin", "SuperUser@1");
        Session target = loginNewUser();
        long id = idOf(target);

        mvc.perform(get("/api/demo/moderator").header("Authorization", target.bearer())).andExpect(status().isForbidden());

        mvc.perform(put("/api/admin/users/{id}/role", id).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"MODERATOR\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("MODERATOR"));

        // The old token carries the old role, so it is refused with token_stale...
        mvc.perform(get("/api/demo/moderator").header("Authorization", target.bearer()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("token_stale"));
        // ...and the client refreshes to get a token with the new role.
        Session upgraded = refreshed(target);
        mvc.perform(get("/api/demo/moderator").header("Authorization", upgraded.bearer())).andExpect(status().isOk());

        mvc.perform(get("/api/admin/audit").param("type", "ROLE_CHANGED").header("Authorization", admin.bearer()))
                .andExpect(jsonPath("$.content[0].actor").value("admin"))
                .andExpect(jsonPath("$.content[0].detail").value("USER → MODERATOR"));
    }

    @Test
    @DisplayName("disabling an account signs it out everywhere and blocks login; enabling restores it")
    void disableAndEnable() throws Exception {
        Session admin = login("admin", "SuperUser@1");
        Session target = loginNewUser();
        long id = idOf(target);

        mvc.perform(put("/api/admin/users/{id}/status", id).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.activeSessions").value(0));

        mvc.perform(get("/api/account").header("Authorization", target.bearer())).andExpect(status().isUnauthorized());
        refresh(target.refreshCookie()).andExpect(status().isUnauthorized());
        postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Str0ngPass!\"}", target.username()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("account_disabled"));

        mvc.perform(put("/api/admin/users/{id}/status", id).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":true}"))
                .andExpect(status().isOk());
        login(target.username(), "Str0ngPass!");
    }

    @Test
    @DisplayName("an admin can unlock a locked account and sign a user out everywhere")
    void unlockAndRevoke() throws Exception {
        Session admin = login("admin", "SuperUser@1");
        String username = registerUser();
        long id = idOf(login(username, "Str0ngPass!"));
        for (int i = 0; i < 5; i++) {
            postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Wrong%d\"}", username, i));
        }
        mvc.perform(get("/api/admin/users").param("q", username).header("Authorization", admin.bearer()))
                .andExpect(jsonPath("$.content[0].locked").value(true));

        mvc.perform(post("/api/admin/users/{id}/unlock", id).header("Authorization", admin.bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(false));
        Session again = login(username, "Str0ngPass!");

        mvc.perform(delete("/api/admin/users/{id}/sessions", id).header("Authorization", admin.bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeSessions").value(0));
        mvc.perform(get("/api/account").header("Authorization", again.bearer())).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("admins can't lock themselves out or remove the last admin")
    void adminSafetyRules() throws Exception {
        Session admin = login("admin", "SuperUser@1");
        long adminId = idOf(admin);
        mvc.perform(put("/api/admin/users/{id}/role", adminId).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"USER\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("cannot_change_own_role"));
        mvc.perform(put("/api/admin/users/{id}/status", adminId).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("cannot_disable_self"));

        // Promote a second admin; it can't demote the original while that one is... still not the last.
        Session other = loginNewUser();
        long otherId = idOf(other);
        mvc.perform(put("/api/admin/users/{id}/role", otherId).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk());
        Session otherAdmin = refreshed(other);
        mvc.perform(put("/api/admin/users/{id}/role", adminId).header("Authorization", otherAdmin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"USER\"}"))
                .andExpect(status().isOk());
        // Now otherAdmin is the only admin; the demoted admin can't act any more.
        mvc.perform(put("/api/admin/users/{id}/role", otherId).header("Authorization", admin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"USER\"}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("token_stale"));
        // Restore the original admin for the other tests.
        mvc.perform(put("/api/admin/users/{id}/role", adminId).header("Authorization", otherAdmin.bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"ADMIN\"}"))
                .andExpect(status().isOk());
        mvc.perform(put("/api/admin/users/{id}/role", otherId).header("Authorization", login("admin", "SuperUser@1").bearer())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"role\":\"USER\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("the public endpoints and docs need no token")
    void publicEndpoints() throws Exception {
        mvc.perform(get("/api/auth/demo-accounts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.accounts", hasSize(3)));
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mvc.perform(get("/index.html")).andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    private long idOf(Session s) throws Exception {
        String body = mvc.perform(get("/api/account").header("Authorization", s.bearer()))
                .andReturn().getResponse().getContentAsString();
        return ((Number) JsonPath.read(body, "$.id")).longValue();
    }
}
