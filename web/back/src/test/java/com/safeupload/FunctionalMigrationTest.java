package com.safeupload;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.safeupload.application.AgentService;
import com.safeupload.infrastructure.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:migration;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop", "spring.h2.console.enabled=false"
})
@AutoConfigureMockMvc
class FunctionalMigrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired EndpointRepository endpoints;
    @Autowired ReceivedEventRepository events;
    @Autowired UsuarioRepository users;
    @Autowired SessaoRepository sessions;
    @Autowired AgentService agents;
    @MockBean Clock clock;
    private MockHttpSession session;
    private final Instant now = Instant.parse("2026-10-04T12:00:00Z");

    @BeforeEach
    void setup() throws Exception {
        events.deleteAll();
        endpoints.deleteAll();
        sessions.deleteAll();
        users.deleteAll();
        when(clock.instant()).thenReturn(now);
        when(clock.getZone()).thenReturn(ZoneOffset.UTC);
        postJson("/api/auth/cadastro", Map.of("nomeCompleto", "Teste Migração", "username", "teste",
                "email", "teste@example.com", "cpf", "52998224725", "senha", "teste-local-123",
                "confirmarSenha", "teste-local-123")).andExpect(status().isCreated());
        session = (MockHttpSession) postJson("/api/auth/login", Map.of("email", "teste@example.com", "senha", "teste-local-123"))
                .andExpect(status().isOk()).andReturn().getRequest().getSession(false);
    }

    @Test
    void localAngularOriginsCanUseSessionApi() throws Exception {
        for (String origin : List.of("http://localhost:4200", "http://127.0.0.1:4200")) {
            mvc.perform(options("/api/auth/login").header("Origin", origin)
                    .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", origin));
        }
        mvc.perform(options("/api/auth/login").header("Origin", "https://untrusted.example")
                .header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden());
    }

    @Test
    void emptyPagesAndSessionHaveRealData() throws Exception {
        mvc.perform(get("/api/painel").session(session)).andExpect(status().isOk())
                .andExpect(jsonPath("$.resumo.total").value(0)).andExpect(jsonPath("$.recentes").isEmpty())
                .andExpect(jsonPath("$.tendencia.length()").value(7)).andExpect(jsonPath("$.categoriasAtivas.length()").value(5));
        mvc.perform(get("/api/endpoints").session(session)).andExpect(jsonPath("$.resumo.total").value(0))
                .andExpect(jsonPath("$.itens").isEmpty());
        mvc.perform(get("/api/auditoria").session(session)).andExpect(jsonPath("$.eventos").isEmpty());
        mvc.perform(get("/api/auth/me").session(session)).andExpect(jsonPath("$.nomeCompleto").value("Teste Migração"))
                .andExpect(jsonPath("$.idUsuario").isNumber()).andExpect(jsonPath("$.senha").doesNotExist());
    }

    @Test
    void administrativeReadsRequireActiveSessionAndLogoutInvalidatesIt() throws Exception {
        for (String route : List.of("/api/painel", "/api/auditoria", "/api/endpoints")) {
            mvc.perform(get(route)).andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/auth/logout").session(session)).andExpect(status().isOk());
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void blockedUserLosesAccessEvenWithExistingSession() throws Exception {
        var user = users.findByEmail("teste@example.com").orElseThrow();
        user.setBloqueado(true);
        users.save(user);
        mvc.perform(get("/api/painel").session(session)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/me").session(session)).andExpect(status().isUnauthorized());
    }

    @Test
    void policyMatchesAgentContract() throws Exception {
        mvc.perform(get("/agent/policy").param("endpointId", "PC-01")).andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1)).andExpect(jsonPath("$.activeCategories[4]").value("Secret"))
                .andExpect(jsonPath("$.monitoredScopes.extensions.length()").value(5))
                .andExpect(jsonPath("$.monitoredScopes.destinationPaths[0]").value("C:\\SafeUpload\\Escopo Monitorado"))
                .andExpect(jsonPath("$.maxFileSizeMb").value(20)).andExpect(jsonPath("$.inspectionTimeoutSeconds").value(5))
                .andExpect(jsonPath("$.failOpen").value(true)).andExpect(jsonPath("$.overrideAllowed").value(false));
    }

    @Test
    void heartbeatUpsertsAndOfflineBoundaryIsNinetySeconds() throws Exception {
        heartbeat("PC-01", "Windows 11 Pro");
        heartbeat("PC-01", "Windows 11 Pro");
        assertThat(endpoints.count()).isEqualTo(1);
        when(clock.instant()).thenReturn(now.plusSeconds(90));
        mvc.perform(get("/api/endpoints").session(session)).andExpect(jsonPath("$.resumo.online").value(1));
        when(clock.instant()).thenReturn(now.plusSeconds(91));
        mvc.perform(get("/api/endpoints").session(session)).andExpect(jsonPath("$.resumo.offline").value(1))
                .andExpect(jsonPath("$.itens[0].status").value("offline"));
    }

    @Test
    void threeVerdictsFlowFromAgentToAllViews() throws Exception {
        heartbeat("PC-01", "Windows 11 Pro");
        List<ObjectNode> batch = List.of(event("PC-01", "Blocked", now, "Cpf", "Cnpj"),
                event("PC-01", "Approved", now.minusSeconds(1)),
                event("PC-01", "AllowedWithoutInspection", now.minusSeconds(2)));
        postJson("/agent/events", Map.of("events", batch)).andExpect(status().isOk())
                .andExpect(jsonPath("$.acceptedEvents").value(3)).andExpect(jsonPath("$.acceptedOverrides").value(0));
        mvc.perform(get("/api/painel").session(session)).andExpect(jsonPath("$.resumo.total").value(3))
                .andExpect(jsonPath("$.resumo.bloqueados").value(1)).andExpect(jsonPath("$.resumo.aprovados").value(1))
                .andExpect(jsonPath("$.resumo.liberadosSemInspecao").value(1))
                .andExpect(jsonPath("$.categoriasBloqueadas.length()").value(2));
        mvc.perform(get("/api/endpoints").session(session)).andExpect(jsonPath("$.itens[0].inspecoes7d").value(3));
        mvc.perform(get("/api/auditoria").session(session).param("endpoint", "PC-01"))
                .andExpect(jsonPath("$.resumo.total").value(3))
                .andExpect(jsonPath("$.eventos[2].notInspectedReason").value("inspection_timeout"));
        mvc.perform(get("/api/auditoria").session(session).param("endpoint", "OUTRO"))
                .andExpect(jsonPath("$.resumo.total").value(0));
    }

    @Test
    void replayIsIdempotentIncludingOverridesAndTransportFlag() throws Exception {
        ObjectNode event = event("PC-01", "Blocked", now, "Secret");
        Map<String, Object> override = Map.of("eventId", event.get("eventId").asText(), "justification", "Revisão",
                "occurredAtUtc", now.toString(), "userName", "teste", "endpointId", "PC-01");
        Map<String, Object> batch = Map.of("events", List.of(event, event), "overrides", List.of(override));
        postJson("/agent/events", batch).andExpect(status().isOk());
        event.put("dispatched", true);
        postJson("/agent/events", batch).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(2));
        assertThat(events.count()).isEqualTo(2);
        assertThat(agents.auditEvents()).hasSize(1);
    }

    @Test
    void conflictingReplayRollsBackWholeBatch() throws Exception {
        ObjectNode original = event("PC-01", "Approved", now);
        postJson("/agent/events", Map.of("events", List.of(original))).andExpect(status().isOk());
        ObjectNode changed = original.deepCopy().put("fileName", "outro.txt");
        postJson("/agent/events", Map.of("events", List.of(event("PC-02", "Blocked", now), changed)))
                .andExpect(status().isConflict());
        assertThat(events.count()).isEqualTo(1);
        assertThat(agents.auditEvents().getFirst().fileName()).isEqualTo("arquivo.txt");
    }

    @Test
    void invalidTimestampOrEnumRejectsEntireBatch() throws Exception {
        for (ObjectNode invalid : List.of(
                event("PC", "Approved", now).put("occurredAtUtc", "2026-10-04T12:00:00"),
                event("PC", "Unknown", now), event("PC", "Approved", now).put("sizeBytes", -1),
                event("PC", "Approved", now).put("verdict", 0))) {
            postJson("/agent/events", Map.of("events", List.of(event("PC", "Approved", now), invalid)))
                    .andExpect(status().isUnprocessableEntity());
        }
        assertThat(events.count()).isZero();
        postJson("/agent/heartbeat", Map.of("endpointId", "")).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void invalidOverrideAlsoPreventsAcknowledgingValidEvents() throws Exception {
        postJson("/agent/events", Map.of("events", List.of(event("PC", "Approved", now)),
                "overrides", List.of(Map.of("eventId", UUID.randomUUID(), "occurredAtUtc", "2026-10-04T12:00:00"))))
                .andExpect(status().isUnprocessableEntity());
        assertThat(events.count()).isZero();
    }

    @Test
    void endpointFiltersPreserveGlobalTotalsAndExcludeFutureInspections() throws Exception {
        heartbeat("FINANCEIRO-01", "Windows 11 Pro");
        heartbeat("RH-01", "Windows 10");
        heartbeat("LINUX-01", "Linux");
        postJson("/agent/events", Map.of("events", List.of(
                event("FINANCEIRO-01", "Approved", now.minus(Duration.ofDays(7))),
                event("FINANCEIRO-01", "Approved", now.plusSeconds(1)),
                event("FINANCEIRO-01", "Approved", now.minus(Duration.ofDays(7)).minusSeconds(1)))))
                .andExpect(status().isOk());
        mvc.perform(get("/api/endpoints").session(session).param("q", "financeiro").param("os", "win11").param("status", "online"))
                .andExpect(jsonPath("$.resumo.total").value(3)).andExpect(jsonPath("$.itens.length()").value(1))
                .andExpect(jsonPath("$.itens[0].inspecoes7d").value(1));
    }

    @Test
    void dashboardUsesSevenUtcCalendarDaysAndSixRecentEvents() throws Exception {
        List<ObjectNode> batch = new ArrayList<>();
        batch.add(event("PC", "Blocked", Instant.parse("2026-09-28T00:00:00Z"), "Cpf", "Cpf"));
        batch.add(event("PC", "Blocked", Instant.parse("2026-09-27T23:59:59Z"), "Secret"));
        batch.add(event("PC", "Approved", now.plusSeconds(1)));
        for (int index = 0; index < 7; index++) batch.add(event("PC", "Approved", now.minusSeconds(index)));
        postJson("/agent/events", Map.of("events", batch)).andExpect(status().isOk());
        mvc.perform(get("/api/painel").session(session)).andExpect(jsonPath("$.resumo.total").value(8))
                .andExpect(jsonPath("$.tendencia[0].data").value("2026-09-28"))
                .andExpect(jsonPath("$.tendencia[0].quantidade").value(1))
                .andExpect(jsonPath("$.categoriasBloqueadas[0].quantidade").value(1))
                .andExpect(jsonPath("$.recentes.length()").value(6));
    }

    @Test
    void offsetDatesSortByInstantAndAreNormalized() throws Exception {
        ObjectNode earlier = event("PC", "Approved", now).put("occurredAtUtc", "2026-10-04T11:00:00+02:00").put("fileName", "anterior.txt");
        ObjectNode later = event("PC", "Approved", now).put("occurredAtUtc", "2026-10-04T08:00:00-03:00").put("fileName", "recente.txt");
        postJson("/agent/events", Map.of("events", List.of(earlier, later))).andExpect(status().isOk());
        mvc.perform(get("/api/auditoria").session(session)).andExpect(jsonPath("$.eventos[0].fileName").value("recente.txt"));
        assertThat(agents.auditEvents().getFirst().occurredAtUtc().getOffset()).isEqualTo(ZoneOffset.UTC);
    }

    private void heartbeat(String id, String os) throws Exception {
        postJson("/agent/heartbeat", Map.of("endpointId", id, "hostname", id, "os", os,
                "agentVersion", "1.0.0", "policyVersion", 1)).andExpect(status().isOk())
                .andExpect(jsonPath("$.endpointId").value(id)).andExpect(jsonPath("$.serverTimeUtc").exists());
    }

    private ObjectNode event(String endpoint, String verdict, Instant occurredAt, String... categories) {
        ObjectNode event = mapper.createObjectNode();
        event.put("eventId", UUID.randomUUID().toString());
        event.put("occurredAtUtc", occurredAt.toString());
        event.put("endpointId", endpoint);
        event.put("userName", "teste");
        event.put("fileName", "arquivo.txt");
        event.put("extension", ".txt");
        event.put("sizeBytes", 100);
        event.put("verdict", verdict);
        event.set("categories", mapper.valueToTree(categories));
        event.putArray("maskedSnippets");
        event.put("processName", "editor.exe");
        event.put("processId", 123);
        event.put("destinationPath", "C:\\SafeUpload\\Escopo Monitorado\\arquivo.txt");
        event.put("policyVersion", 1);
        event.put("elapsedMs", 12);
        event.put("dispatched", false);
        if (verdict.equals("AllowedWithoutInspection")) event.put("notInspectedReason", "inspection_timeout");
        return event;
    }

    private ResultActions postJson(String path, Object body) throws Exception {
        return mvc.perform(post(path).contentType("application/json").content(mapper.writeValueAsBytes(body)));
    }
}
