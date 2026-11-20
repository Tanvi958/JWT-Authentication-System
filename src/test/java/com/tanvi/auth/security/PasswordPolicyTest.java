package com.tanvi.auth.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @Test
    void acceptsAStrongPassword() {
        assertThat(policy.violations("Kettle7Moon", "riya", "riya@example.com")).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({
            "Ab1,                 at least 8 characters",
            "alllowercase1,       an upper-case letter",
            "ALLUPPERCASE1,       a lower-case letter",
            "NoDigitsHere,        a digit",
            "Password1,           not a commonly used password",
            "Riya2026Rocks,       must not contain your username",
            "Kettle7RIYA.S,       must not contain your e-mail name"
    })
    void reportsEachBrokenRule(String password, String expected) {
        assertThat(policy.violations(password, "riya", "riya.s@example.com")).contains(expected);
    }

    @Test
    void enforcesTheBcrypt72ByteLimit() {
        assertThat(policy.violations("Aa1" + "x".repeat(70), "u", "u@example.com")).contains("at most 72 bytes");
    }

    @Test
    void describesViolationsReadably() {
        assertThat(policy.describe(policy.violations("abc", null, null)))
                .isEqualTo("Password needs: at least 8 characters, an upper-case letter, a digit");
    }
}
