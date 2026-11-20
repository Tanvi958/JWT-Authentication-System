package com.tanvi.auth.config;

import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Creates one account per role when the database is empty, so the app can be tried straight away. */
@Component
@ConditionalOnProperty(name = "app.demo.seed-users", havingValue = "true")
public class DemoUserSeeder implements ApplicationRunner {

    public record DemoAccount(String username, String password, Role role, String fullName, String email) {
    }

    public static final List<DemoAccount> ACCOUNTS = List.of(
            new DemoAccount("admin", "SuperUser@1", Role.ADMIN, "Asha Admin", "admin@demo.local"),
            new DemoAccount("moderator", "Reviewer@1", Role.MODERATOR, "Mohan Moderator", "moderator@demo.local"),
            new DemoAccount("user", "Member@123", Role.USER, "Uma User", "user@demo.local"));

    private static final Logger log = LoggerFactory.getLogger(DemoUserSeeder.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public DemoUserSeeder(UserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (users.count() > 0) {
            return;
        }
        ACCOUNTS.forEach(a -> users.save(new User(a.username(), a.email(), a.fullName(),
                passwordEncoder.encode(a.password()), a.role())));
        log.info("Created demo accounts: {}", ACCOUNTS.stream().map(DemoAccount::username).toList());
    }
}
