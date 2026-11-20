package com.tanvi.auth.security;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Password rules: 8-72 characters (BCrypt reads at most 72 bytes), upper- and lower-case letters and a digit,
 * not a well-known password, and not containing the username or the e-mail name.
 */
@Component
public class PasswordPolicy {

    private static final Set<String> COMMON = Set.of(
            "password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890",
            "qwerty123", "qwertyuiop", "iloveyou", "admin123", "welcome1", "welcome123", "letmein1",
            "abc12345", "football1", "monkey123", "sunshine1", "princess1", "changeme", "p@ssw0rd");

    /** Returns the broken rules, or an empty list when the password is acceptable. */
    public List<String> violations(String password, String username, String email) {
        List<String> problems = new ArrayList<>();
        if (password == null || password.length() < 8) {
            problems.add("at least 8 characters");
        }
        if (password != null && password.getBytes(StandardCharsets.UTF_8).length > 72) {
            problems.add("at most 72 bytes");
        }
        if (password == null) {
            return problems;
        }
        if (password.chars().noneMatch(Character::isUpperCase)) problems.add("an upper-case letter");
        if (password.chars().noneMatch(Character::isLowerCase)) problems.add("a lower-case letter");
        if (password.chars().noneMatch(Character::isDigit)) problems.add("a digit");

        String lower = password.toLowerCase();
        if (COMMON.contains(lower)) {
            problems.add("not a commonly used password");
        }
        if (username != null && username.length() >= 3 && lower.contains(username.toLowerCase())) {
            problems.add("must not contain your username");
        }
        String emailName = email == null ? null : email.split("@")[0].toLowerCase();
        if (emailName != null && emailName.length() >= 3 && lower.contains(emailName)) {
            problems.add("must not contain your e-mail name");
        }
        return problems;
    }

    public String describe(List<String> violations) {
        return "Password needs: " + String.join(", ", violations);
    }
}
