package com.safeupload.presentation.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public SecurityConfig() {}


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            SecurityContextRepository securityContextRepository) throws Exception {

        http
            .securityContext(context -> context
                .securityContextRepository(securityContextRepository)
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/decision", "/auth/login", "/auth/firstregister", "/error").permitAll()
                // O agente não tem sessão: AgentAuthFilter confere a assinatura Ed25519 de cada requisição.
                .requestMatchers("/agent/**").permitAll()
                .requestMatchers("/auth/me", "/auth/logout").authenticated()
                .requestMatchers("/auth/normalregister/empresa/set").hasRole("ROOT")
                .anyRequest().hasAnyRole("ADMIN", "ROOT")
            )
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            // Sem token CSRF: o cookie de sessão é SameSite=Lax e a API só aceita JSON (exige preflight entre origens,
            // e não há CORS liberado). O agente não usa cookie.
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
