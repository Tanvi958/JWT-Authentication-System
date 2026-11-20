package com.tanvi.auth.support;

import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.Cookie;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Helpers shared by the integration tests: register, log in, refresh. */
public abstract class ApiTestSupport {

    private static final AtomicInteger SEQ = new AtomicInteger();

    @Autowired
    protected MockMvc mvc;

    /** What a client holds after signing in. */
    public record Session(String accessToken, Cookie refreshCookie, String username) {
        public String bearer() {
            return "Bearer " + accessToken;
        }
    }

    protected static String json(String template, Object... args) {
        return template.formatted(args);
    }

    protected ResultActions postJson(String url, String body) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body)
                .header(HttpHeaders.USER_AGENT, "MockMvc test client"));
    }

    /** Registers a fresh user (unique name) with a valid password and returns the username. */
    protected String registerUser() throws Exception {
        String username = "tester" + SEQ.incrementAndGet() + "x" + System.nanoTime() % 100000;
        postJson("/api/auth/register", json("""
                {"username":"%s","email":"%s@example.com","fullName":"Test User","password":"Str0ngPass!"}
                """, username, username)).andExpect(status().isCreated());
        return username;
    }

    protected Session login(String login, String password) throws Exception {
        MockHttpServletResponse res = postJson("/api/auth/login",
                json("{\"login\":\"%s\",\"password\":\"%s\"}", login, password))
                .andExpect(status().isOk())
                .andReturn().getResponse();
        return new Session(JsonPath.read(res.getContentAsString(), "$.accessToken"),
                res.getCookie("refresh_token"), login);
    }

    protected Session loginNewUser() throws Exception {
        return login(registerUser(), "Str0ngPass!");
    }

    protected ResultActions refresh(Cookie cookie) throws Exception {
        var request = post("/api/auth/refresh").header(HttpHeaders.USER_AGENT, "MockMvc test client");
        if (cookie != null) request.cookie(cookie);
        return mvc.perform(request);
    }

    protected Session refreshed(Session s) throws Exception {
        MockHttpServletResponse res = refresh(s.refreshCookie()).andExpect(status().isOk()).andReturn().getResponse();
        return new Session(JsonPath.read(res.getContentAsString(), "$.accessToken"),
                res.getCookie("refresh_token"), s.username());
    }
}
