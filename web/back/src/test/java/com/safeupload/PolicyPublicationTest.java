package com.safeupload;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safeupload.application.AgentService;
import com.safeupload.application.PolicyService;
import com.safeupload.application.dto.PolicyPublication;
import com.safeupload.application.dto.AgentContracts.Heartbeat;
import com.safeupload.infrastructure.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:policy;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop"})
@AutoConfigureMockMvc
class PolicyPublicationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired JdbcTemplate jdbc;
    @Autowired AgentService agents;
    @Autowired PolicyService policies;
    @Autowired UsuarioRepository users;
    @Autowired SessaoRepository sessions;
    private MockHttpSession admin;

    @BeforeEach void setup() throws Exception {
        jdbc.update("delete from agent_published_policies");
        jdbc.update("delete from agent_endpoints");
        sessions.deleteAll(); users.deleteAll();
        mvc.perform(post("/api/auth/cadastro").contentType("application/json").content(mapper.writeValueAsString(Map.of(
                "nomeCompleto", "Administrador Teste", "username", "admin", "email", "admin@example.com", "cpf", "52998224725",
                "senha", "teste-local-123", "confirmarSenha", "teste-local-123")))).andExpect(status().isCreated());
        admin = (MockHttpSession) mvc.perform(post("/api/auth/login").contentType("application/json")
                .content("{\"email\":\"admin@example.com\",\"senha\":\"teste-local-123\"}"))
                .andExpect(status().isOk()).andReturn().getRequest().getSession(false);
        agents.heartbeat(new Heartbeat("PC-A", "PC-A", "Windows 11", "1.0", 1));
        agents.heartbeat(new Heartbeat("PC-B", "PC-B", "Windows 11", "1.0", 1));
    }

    @Test void publishMapsCategoriesAndSeparatesComputers() throws Exception {
        publish(document("PC-A", "bloquear", "cpf", "credenciais", "cartao_credito", "cnpj"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.version").value(2))
                .andExpect(jsonPath("$.policy.auditOnly").value(false))
                .andExpect(jsonPath("$.policy.activeCategories.length()").value(5));
        mvc.perform(get("/agent/policy").param("endpointId", "PC-A"))
                .andExpect(jsonPath("$.version").value(2)).andExpect(jsonPath("$.clipboard.mode").value("Off"));
        mvc.perform(get("/agent/policy").param("endpointId", "PC-B"))
                .andExpect(jsonPath("$.version").value(1));
        publish(document("PC-A", "bloquear", "cnpj"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.version").value(3))
                .andExpect(jsonPath("$.policy.auditOnly").value(false))
                .andExpect(jsonPath("$.policy.activeCategories[0]").value("Cnpj"));
        mvc.perform(get("/api/politicas").session(admin)).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].version").value(3));
        mvc.perform(post("/agent/heartbeat").contentType("application/json").content(mapper.writeValueAsString(
                new Heartbeat("PC-A", "PC-A", "Windows", "1.0", 2))))
                .andExpect(jsonPath("$.policyVersion").value(3));
    }

    @Test void invalidPublicationsNeverReplaceLastValidPolicy() throws Exception {
        publish(document("PC-A", "bloquear", "cpf")).andExpect(status().isOk());
        for (var rule : List.of("rg", "dados_saude", "dados_bancarios", "dados_pessoais", "documentos_confidenciais", "999"))
            publish(document("PC-A", "bloquear", "cpf", rule)).andExpect(status().isBadRequest());
        publish(document("PC-A", "bloquear", "cpf", "cpf")).andExpect(status().isBadRequest());
        publish(document("PC-A", "ignorar", "cpf")).andExpect(status().isBadRequest());
        publish(document("PC-A", "alertar", "cpf")).andExpect(status().isBadRequest());
        publish(document("PC-A", "bloquear")).andExpect(status().isBadRequest());
        publish(document("DESCONHECIDO", "bloquear", "cpf")).andExpect(status().isBadRequest());
        var oldJson = document("PC-A", "bloquear", "cpf");
        oldJson.put("destino", Map.of("ip", "312312312321321"));
        publish(oldJson).andExpect(status().isBadRequest());
        oldJson.put("destino", Map.of("endpointId", "PC-A", "ip", "127.0.0.1"));
        publish(oldJson).andExpect(status().isBadRequest());
        var wrongSchema = document("PC-A", "bloquear", "cpf");
        wrongSchema.put("versao", "2.0");
        publish(wrongSchema).andExpect(status().isBadRequest());
        mvc.perform(get("/agent/policy").param("endpointId", "PC-A"))
                .andExpect(jsonPath("$.version").value(2)).andExpect(jsonPath("$.activeCategories.length()").value(1));
    }

    @Test void concurrentPublicationsAllocateDistinctMonotonicVersions() throws Exception {
        var request = mapper.convertValue(document("PC-A", "bloquear", "cpf"), PolicyPublication.Request.class);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = executor.submit(() -> { start.await(); return policies.publish(request).version(); });
            var second = executor.submit(() -> { start.await(); return policies.publish(request).version(); });
            start.countDown();
            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(2, 3);
        }
        assertThat(policies.policy("PC-A").version()).isEqualTo(3);
    }

    @Test void publicationRequiresActiveAdministrator() throws Exception {
        String json = mapper.writeValueAsString(document("PC-A", "bloquear", "cpf"));
        mvc.perform(post("/api/politicas").contentType("application/json").content(json)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/politicas")).andExpect(status().isUnauthorized());
        var user = users.findByEmail("admin@example.com").orElseThrow();
        user.setRole("user"); users.save(user);
        mvc.perform(post("/api/politicas").session(admin).contentType("application/json").content(json)).andExpect(status().isForbidden());
        mvc.perform(get("/api/politicas").session(admin)).andExpect(status().isForbidden());
    }

    private Map<String, Object> document(String endpoint, String action, String... rules) {
        var request = new HashMap<String, Object>();
        request.put("versao", "1.0"); request.put("nome", "Proteção de teste");
        request.put("destino", Map.of("endpointId", endpoint)); request.put("acao", action);
        request.put("regras", Arrays.stream(rules).map(r -> Map.of("tipo", r, "nome", r)).toList());
        request.put("origem", "console-administrativo");
        return request;
    }
    private org.springframework.test.web.servlet.ResultActions publish(Map<String, Object> request) throws Exception {
        return mvc.perform(post("/api/politicas").session(admin).contentType("application/json").content(mapper.writeValueAsString(request)));
    }
}
