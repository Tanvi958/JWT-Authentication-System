package com.tanvi.auth.security;

import com.tanvi.auth.config.AppProperties;
import com.tanvi.auth.repository.RefreshTokenRepository;
import com.tanvi.auth.repository.UserRepository;
import com.tanvi.auth.web.error.ErrorResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Clock;
import java.util.List;

/**
 * Stateless security: no HTTP session, no form login. Each API request is authenticated by
 * {@link JwtAuthenticationFilter}; permissions are checked with {@code @PreAuthorize} on controllers.
 *
 * <p>CSRF protection is off because the API authenticates with a header, which a cross-site form can't set.
 * The one cookie (the refresh token) is {@code HttpOnly}, {@code SameSite=Strict} and scoped to
 * {@code /api/auth}, so other sites can't send it either.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] PUBLIC_GET = {
            "/", "/index.html", "/assets/**", "/favicon.svg", "/error",
            "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/actuator/health/**",
            "/api/auth/demo-accounts", "/api/demo/public"
    };

    private static final String[] PUBLIC_POST = {
            "/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout"
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, AppProperties props, JwtService jwtService,
                                            UserRepository users, RefreshTokenRepository refreshTokens) throws Exception {
        // Created here (not as @Component beans) so Spring Boot doesn't also register them as servlet filters.
        var jwtFilter = new JwtAuthenticationFilter(jwtService, users, refreshTokens);
        var rateLimitFilter = new RateLimitFilter(props.rateLimit().authRequestsPerMinute(), Clock.systemUTC());

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource(props)))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                        + "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'"))
                        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, PUBLIC_GET).permitAll()
                        .requestMatchers(HttpMethod.POST, PUBLIC_POST).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler((req, res, e) -> ErrorResponse.write(res, 403, "Forbidden",
                                "access_denied", "You don't have permission to do this", req.getRequestURI())))
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Delegating encoder: hashes are stored as {@code {bcrypt}$2a$10$...}, so the algorithm can be upgraded
     * later without breaking existing passwords.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Loads accounts from the database. Login itself goes through AuthService (which also handles lockout);
     * this bean keeps Spring Boot from creating its default in-memory user.
     */
    @Bean
    UserDetailsService userDetailsService(UserRepository users) {
        return username -> users.findByUsername(username.toLowerCase())
                .map(u -> User.withUsername(u.getUsername())
                        .password(u.getPasswordHash())
                        .authorities(u.getRole().authorities())
                        .disabled(!u.isEnabled())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

    /** Cross-origin access is off unless CORS_ALLOWED_ORIGINS lists a separate front-end. */
    private CorsConfigurationSource corsConfigurationSource(AppProperties props) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        List<String> origins = props.cors().allowedOrigins() == null ? List.of()
                : props.cors().allowedOrigins().stream().filter(o -> !o.isBlank()).toList();
        if (!origins.isEmpty()) {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(origins);
            config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
            config.setAllowCredentials(true);
            config.setMaxAge(3600L);
            source.registerCorsConfiguration("/api/**", config);
        }
        return source;
    }
}
