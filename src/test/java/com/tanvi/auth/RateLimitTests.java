package com.tanvi.auth;

import com.tanvi.auth.support.ApiTestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:rate_limit;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "app.rate-limit.auth-requests-per-minute=3"})
@AutoConfigureMockMvc
class RateLimitTests extends ApiTestSupport {

    @Test
    void loginIsRateLimitedPerClient() throws Exception {
        for (int i = 0; i < 3; i++) {
            postJson("/api/auth/login", "{\"login\":\"someone\",\"password\":\"Guess123\"}")
                    .andExpect(status().isUnauthorized());
        }
        postJson("/api/auth/login", "{\"login\":\"someone\",\"password\":\"Guess123\"}")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("rate_limited"))
                .andExpect(jsonPath("$.message", containsString("Try again in")))
                .andExpect(header().exists("Retry-After"));

        // Other endpoints are not affected.
        mvc.perform(get("/api/demo/public")).andExpect(status().isOk());
    }
}
