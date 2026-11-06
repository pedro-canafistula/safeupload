package com.safeupload.security;

import com.safeupload.presentation.config.SecurityConfig;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Exercise the actual security chain before any administrative side effect.
// Business/controller validation and signed device requests keep their own tests.
@SpringBootTest(classes = AdministrativeOperationsSecurityTest.TestApp.class)
@AutoConfigureMockMvc
class AdministrativeOperationsSecurityTest {
    static final List<String> ADMIN_PATHS = List.of("/admin/token", "/admin/policy/set", "/politicas",
        "/auth/normalregister/empresa/set", "/auth/normalregister/empresa/list", "/auth/normalregister/usuario/set");

    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class,
        JpaRepositoriesAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
    @Import({SecurityConfig.class, TestEndpoints.class})
    static class TestApp { }

    @RestController
    static class TestEndpoints {
        final AtomicInteger calls = new AtomicInteger();
        @RequestMapping({"/admin/token", "/admin/policy/set", "/politicas", "/auth/normalregister/empresa/set",
            "/auth/normalregister/empresa/list", "/auth/normalregister/usuario/set", "/auth/firstregister",
            "/agent/heartbeat", "/agent/api/policy", "/agent/events"})
        Map<String, String> handle() { calls.incrementAndGet(); return Map.of("status", "OK"); }
    }

    @Autowired MockMvc mvc;
    @Autowired TestEndpoints endpoints;
    @BeforeEach void reset() { endpoints.calls.set(0); }

    MockHttpSession session(String role) {
        var session = new MockHttpSession();
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken("synthetic-admin", null,
            List.of(new SimpleGrantedAuthority("ROLE_" + role))));
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        return session;
    }

    HttpMethod method(String path) { return path.endsWith("/list") || path.endsWith("/policy") ? HttpMethod.GET : HttpMethod.POST; }

    @Test void administrativeActionsDenyAnonymousAndNonAdminBeforeTheController() throws Exception {
        for (String path : ADMIN_PATHS) {
            mvc.perform(request(method(path), path)).andExpect(status().isUnauthorized());
            for (String role : List.of("USER", "UNKNOWN", "")) {
                mvc.perform(request(method(path), path).session(session(role))).andExpect(status().isForbidden());
            }
        }
        assertThat(endpoints.calls.get()).isZero();
    }

    @Test void adminAndRootKeepAccessToAdministrativeActions() throws Exception {
        for (String path : ADMIN_PATHS) {
            for (String role : List.of("ADMIN", "ROOT")) {
                mvc.perform(request(method(path), path).session(session(role))).andExpect(status().isOk());
            }
        }
        assertThat(endpoints.calls.get()).isEqualTo(ADMIN_PATHS.size() * 2);
    }

    @Test void firstRegistrationAndDeviceRoutesKeepTheirExistingAuthenticationContracts() throws Exception {
        for (String path : List.of("/auth/firstregister", "/agent/heartbeat", "/agent/api/policy", "/agent/events")) {
            mvc.perform(request(method(path), path)).andExpect(status().isOk());
        }
        assertThat(endpoints.calls.get()).isEqualTo(4);
    }
}
