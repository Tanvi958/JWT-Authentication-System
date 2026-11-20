package com.tanvi.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI authOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("JWT Authentication System API")
                        .version("1.0")
                        .description("""
                                Stateless authentication with short-lived JWT access tokens and rotating refresh \
                                tokens (HttpOnly cookie), plus permission-based access control. \
                                Call POST /api/auth/login (demo: admin / SuperUser@1), then press Authorize and \
                                paste the accessToken."""))
                .components(new Components().addSecuritySchemes("bearer",
                        new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList("bearer"));
    }
}
