package com.tanvi.auth;

import com.tanvi.auth.support.ApiTestSupport;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Registration, login, token refresh with rotation and reuse detection, logout, lockout, password change. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:auth_flow;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "app.rate-limit.auth-requests-per-minute=10000"})
@AutoConfigureMockMvc
class AuthFlowTests extends ApiTestSupport {

    // ---------------------------------------------------------------- register

    @Test
    @DisplayName("register validates input, rejects weak passwords and duplicates")
    void register() throws Exception {
        postJson("/api/auth/register", """
                {"username":"Riya.S","email":"Riya@Example.com","fullName":"Riya S","password":"Kettle7Moon"}
                """)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("riya.s"))
                .andExpect(jsonPath("$.email").value("riya@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.permissions", containsInAnyOrder("profile:read", "profile:write")))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        postJson("/api/auth/register", """
                {"username":"RIYA.s","email":"other@example.com","fullName":"X","password":"Kettle7Moon"}
                """).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("username_taken"));
        postJson("/api/auth/register", """
                {"username":"other","email":"RIYA@example.com","fullName":"X","password":"Kettle7Moon"}
                """).andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("email_taken"));

        postJson("/api/auth/register", """
                {"username":"weak1","email":"weak1@example.com","fullName":"W","password":"password1"}
                """)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("weak_password"))
                .andExpect(jsonPath("$.message", containsString("an upper-case letter")))
                .andExpect(jsonPath("$.message", containsString("not a commonly used password")));
        postJson("/api/auth/register", """
                {"username":"bob","email":"bob@example.com","fullName":"B","password":"Bob12345xyz"}
                """)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message", containsString("must not contain your username")));

        postJson("/api/auth/register", """
                {"username":"a b","email":"nope","fullName":"","password":""}
                """)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("validation_failed"))
                .andExpect(jsonPath("$.fieldErrors.username").exists())
                .andExpect(jsonPath("$.fieldErrors.email").exists())
                .andExpect(jsonPath("$.fieldErrors.fullName").exists())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    // ---------------------------------------------------------------- login

    @Test
    @DisplayName("login returns an access token and an HttpOnly, SameSite=Strict refresh cookie")
    void loginIssuesTokens() throws Exception {
        String username = registerUser();
        var res = postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Str0ngPass!\"}", username.toUpperCase()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.accessToken", matchesPattern("^[\\w-]+\\.[\\w-]+\\.[\\w-]+$")))
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(jsonPath("$.user.username").value(username))
                .andReturn().getResponse();

        String setCookie = res.getHeader("Set-Cookie");
        assertThat(setCookie).startsWith("refresh_token=").contains("HttpOnly", "Secure", "SameSite=Strict",
                "Path=/api/auth", "Max-Age=604800");

        // Login by e-mail works too, and the token opens protected endpoints.
        Session s = login(username + "@example.com", "Str0ngPass!");
        mvc.perform(get("/api/account").header("Authorization", s.bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.lastLoginAt").exists());
    }

    @Test
    @DisplayName("wrong password and unknown user give the same answer")
    void badCredentials() throws Exception {
        String username = registerUser();
        postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Wrong123\"}", username))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("invalid_credentials"))
                .andExpect(jsonPath("$.message").value("Incorrect username/email or password"));
        postJson("/api/auth/login", "{\"login\":\"nobody-here\",\"password\":\"Wrong123\"}")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("invalid_credentials"))
                .andExpect(jsonPath("$.message").value("Incorrect username/email or password"));
    }

    @Test
    @DisplayName("5 wrong passwords lock the account; even the right password is refused while locked")
    void lockout() throws Exception {
        String username = registerUser();
        for (int i = 1; i <= 4; i++) {
            postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Wrong%d\"}", username, i))
                    .andExpect(status().isUnauthorized());
        }
        postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Wrong5\"}", username))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.code").value("account_locked"));
        postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Str0ngPass!\"}", username))
                .andExpect(status().isLocked());

        Session admin = login("admin", "SuperUser@1");
        mvc.perform(get("/api/admin/audit").param("type", "ACCOUNT_LOCKED").header("Authorization", admin.bearer()))
                .andExpect(jsonPath("$.content[0].username").value(username))
                .andExpect(jsonPath("$.content[0].detail").value("5 failed attempts"));
    }

    @Test
    @DisplayName("a successful login resets the failed-attempt counter")
    void successResetsCounter() throws Exception {
        String username = registerUser();
        for (int round = 0; round < 2; round++) {
            for (int i = 0; i < 4; i++) {
                postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Wrong%d\"}", username, i))
                        .andExpect(status().isUnauthorized());
            }
            login(username, "Str0ngPass!");   // 8 failures in total, never 5 in a row → never locked
        }
    }

    // ---------------------------------------------------------------- tokens

    @Test
    @DisplayName("missing, malformed and tampered tokens are rejected with a reason code")
    void badTokens() throws Exception {
        mvc.perform(get("/api/account"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("unauthenticated"))
                .andExpect(header().string("WWW-Authenticate", "Bearer"));
        mvc.perform(get("/api/account").header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("token_invalid"));

        Session s = loginNewUser();
        String[] parts = s.accessToken().split("\\.");
        String forged = parts[0] + "." + parts[1].substring(0, parts[1].length() - 2) + "AA." + parts[2];
        mvc.perform(get("/api/account").header("Authorization", "Bearer " + forged))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("token_invalid"));
    }

    @Test
    @DisplayName("refresh rotates the token; replaying a rotated token revokes the whole session")
    void refreshRotationAndReuseDetection() throws Exception {
        Session first = loginNewUser();
        Session second = refreshed(first);
        assertThat(second.refreshCookie().getValue()).isNotEqualTo(first.refreshCookie().getValue());
        assertThat(second.accessToken()).isNotEqualTo(first.accessToken());

        // The new access token works.
        mvc.perform(get("/api/account").header("Authorization", second.bearer())).andExpect(status().isOk());

        // An attacker replays the old (already rotated) refresh token...
        refresh(first.refreshCookie())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("refresh_token_reused"))
                .andExpect(header().string("Set-Cookie", containsString("Max-Age=0")));

        // ...so the whole session is gone: the current refresh token and access token stop working too.
        refresh(second.refreshCookie())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("session_ended"));
        mvc.perform(get("/api/account").header("Authorization", second.bearer()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("session_ended"));

        Session admin = login("admin", "SuperUser@1");
        mvc.perform(get("/api/admin/audit").param("type", "TOKEN_REUSE_DETECTED").header("Authorization", admin.bearer()))
                .andExpect(jsonPath("$.content[0].username").value(first.username()));
    }

    @Test
    @DisplayName("refresh without or with an unknown cookie is refused")
    void refreshWithoutCookie() throws Exception {
        refresh(null).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("refresh_token_invalid"));
        refresh(new Cookie("refresh_token", "made-up-value"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("refresh_token_invalid"));
    }

    // ---------------------------------------------------------------- logout + sessions

    @Test
    @DisplayName("logout ends the session at once: its access token stops working before it expires")
    void logout() throws Exception {
        Session s = loginNewUser();
        mvc.perform(post("/api/auth/logout").cookie(s.refreshCookie()))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Set-Cookie", containsString("Max-Age=0")));
        mvc.perform(get("/api/account").header("Authorization", s.bearer()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("session_ended"));
        refresh(s.refreshCookie()).andExpect(status().isUnauthorized());
        // Logging out twice is harmless.
        mvc.perform(post("/api/auth/logout").cookie(s.refreshCookie())).andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("sessions list shows each device; one can be signed out without touching the others")
    void sessions() throws Exception {
        String username = registerUser();
        Session laptop = login(username, "Str0ngPass!");
        Session phone = login(username, "Str0ngPass!");

        String body = mvc.perform(get("/api/account/sessions").header("Authorization", laptop.bearer()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[?(@.current == true)]", hasSize(1)))
                .andExpect(jsonPath("$[0].device").value("Test client"))
                .andReturn().getResponse().getContentAsString();
        String phoneSession = com.jayway.jsonpath.JsonPath.<java.util.List<String>>read(body, "$[?(@.current == false)].id").getFirst();

        mvc.perform(delete("/api/account/sessions/{id}", phoneSession).header("Authorization", laptop.bearer()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/account").header("Authorization", phone.bearer())).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/account").header("Authorization", laptop.bearer())).andExpect(status().isOk());

        // Someone else's session id is "not found", never revoked.
        Session stranger = loginNewUser();
        mvc.perform(delete("/api/account/sessions/{id}", phoneSession).header("Authorization", stranger.bearer()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("log out everywhere ends every session of the user")
    void logoutEverywhere() throws Exception {
        String username = registerUser();
        Session a = login(username, "Str0ngPass!");
        Session b = login(username, "Str0ngPass!");
        mvc.perform(post("/api/auth/logout-all").header("Authorization", a.bearer())).andExpect(status().isNoContent());
        mvc.perform(get("/api/account").header("Authorization", a.bearer())).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/account").header("Authorization", b.bearer())).andExpect(status().isUnauthorized());
        refresh(b.refreshCookie()).andExpect(status().isUnauthorized());
    }

    // ---------------------------------------------------------------- account

    @Test
    @DisplayName("changing the password checks the old one, applies the policy and signs out everywhere")
    void changePassword() throws Exception {
        String username = registerUser();
        Session s = login(username, "Str0ngPass!");
        Session other = login(username, "Str0ngPass!");

        mvc.perform(put("/api/account/password").header("Authorization", s.bearer()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Nope1234\",\"newPassword\":\"Better9Pass\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("wrong_current_password"));
        mvc.perform(put("/api/account/password").header("Authorization", s.bearer()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Str0ngPass!\",\"newPassword\":\"Str0ngPass!\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("password_reused"));
        mvc.perform(put("/api/account/password").header("Authorization", s.bearer()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Str0ngPass!\",\"newPassword\":\"short\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("weak_password"));

        mvc.perform(put("/api/account/password").header("Authorization", s.bearer()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Str0ngPass!\",\"newPassword\":\"Better9Pass\"}"))
                .andExpect(status().isNoContent());

        mvc.perform(get("/api/account").header("Authorization", s.bearer())).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/account").header("Authorization", other.bearer())).andExpect(status().isUnauthorized());
        postJson("/api/auth/login", json("{\"login\":\"%s\",\"password\":\"Str0ngPass!\"}", username))
                .andExpect(status().isUnauthorized());
        Session fresh = login(username, "Better9Pass");

        mvc.perform(get("/api/account/events").header("Authorization", fresh.bearer()))
                .andExpect(jsonPath("$[0].type").value("LOGIN_SUCCESS"))
                .andExpect(jsonPath("$[*].type", hasItems("PASSWORD_CHANGED", "REGISTERED", "LOGIN_FAILED")));
    }

    @Test
    @DisplayName("profile can be updated")
    void updateProfile() throws Exception {
        Session s = loginNewUser();
        mvc.perform(put("/api/account").header("Authorization", s.bearer()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"  New Name  \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fullName").value("New Name"));
    }
}
