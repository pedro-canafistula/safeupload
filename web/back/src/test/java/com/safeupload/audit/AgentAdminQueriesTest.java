package com.safeupload.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safeupload.presentation.config.SecurityConfig;
import com.safeupload.presentation.exception.ApiExceptionHandler;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes=AgentAdminQueriesTest.TestApp.class)
@AutoConfigureMockMvc
class AgentAdminQueriesTest {
    static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude={DataSourceAutoConfiguration.class,HibernateJpaAutoConfiguration.class,JpaRepositoriesAutoConfiguration.class})
    @Import({AgentAdminController.class,AgentAdminQueries.class,AgentEventsController.class,AgentEventsStore.class,SecurityConfig.class,ApiExceptionHandler.class})
    static class TestApp {
        @Bean("appDataSource") DataSource dataSource() {
            return new DriverManagerDataSource("jdbc:h2:mem:admin-reads;MODE=MySQL;DB_CLOSE_DELAY=-1", "sa", "");
        }
        @Bean Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
    }
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired DataSource source;
    JdbcTemplate jdbc;
    @BeforeEach void schema() throws Exception {
        jdbc = new JdbcTemplate(source);
        jdbc.execute("DROP TABLE IF EXISTS agent_audit_ingest");
        String ddl = Files.readString(Path.of("../../db/initdb/05_agent_audit_ingest.sql"));
        jdbc.execute(ddl.substring(ddl.indexOf("CREATE TABLE")).replace("CHARACTER SET ascii COLLATE ascii_bin", "")
            .replace("ENGINE=InnoDB DEFAULT CHARSET=utf8mb4", ""));
        jdbc.execute("DROP TABLE IF EXISTS hosts");
        jdbc.execute("CREATE TABLE hosts(id_host INT PRIMARY KEY,hostname VARCHAR(100),sistema_operacional VARCHAR(40),versao_so VARCHAR(20),visto_por_ultimo TIMESTAMP,ativo INT)");
    }
    MockHttpSession session(String role) {
        var session = new MockHttpSession();
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken("test-admin", null, List.of(new SimpleGrantedAuthority("ROLE_"+role))));
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
        return session;
    }
    Map<String,Object> event(String endpoint, String verdict, String channel) {
        var event = new java.util.LinkedHashMap<String,Object>();
        event.put("eventId", UUID.randomUUID().toString()); event.put("occurredAtUtc", NOW.toString());
        event.put("endpointId",endpoint); event.put("userName","synthetic"); event.put("fileName", channel.equals("File") ? "<script>file</script>.txt" : "");
        event.put("extension",".txt"); event.put("sizeBytes",12); event.put("verdict",verdict); event.put("categories",List.of("Cpf"));
        event.put("processName","editor.exe"); event.put("processId",42); event.put("destinationPath","C:\\synthetic");
        event.put("policyVersion",2); event.put("elapsedMs",3); event.put("channel",channel);
        event.put("maskedSnippets",List.of("SENSITIVE-CONTENT-MUST-NOT-RETURN"));
        return event;
    }
    void send(Map<String,Object> event) throws Exception {
        mvc.perform(post("/agent/events").contentType("application/json").content(mapper.writeValueAsString(
            Map.of("schemaVersion",1,"hostname",event.get("endpointId"),"agentVersion","test-version","events",List.of(event)))))
            .andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(1));
    }
    @Test void administrativeReadsRequireAdminOrRootSession() throws Exception {
        for (String path : List.of("/painel","/auditoria","/endpoints")) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
            mvc.perform(get(path).session(session("USER"))).andExpect(status().isForbidden());
            mvc.perform(get(path).session(session("ADMIN"))).andExpect(status().isOk());
            mvc.perform(get(path).session(session("ROOT"))).andExpect(status().isOk());
        }
    }
    @Test void emptyDatabaseHasNoInventedIndicators() throws Exception {
        mvc.perform(get("/painel").session(session("ADMIN"))).andExpect(status().isOk())
            .andExpect(jsonPath("$.resumo.total").value(0)).andExpect(jsonPath("$.recentes").isEmpty());
        mvc.perform(get("/endpoints").session(session("ADMIN"))).andExpect(jsonPath("$.resumo.total").value(0));
    }
    @Test void readsPersistedVerdictsChannelsAndDeduplicatedEventsWithoutSnippets() throws Exception {
        var blocked=event("ALVO","Blocked","File"); send(blocked); send(blocked);
        send(event("ALVO","Approved","File")); send(event("ALVO","AllowedWithoutInspection","Clipboard")); send(event("ALVO","Retained","Web"));
        var old=event("ALVO","Blocked","File"); old.put("occurredAtUtc","2026-10-23T23:59:00Z"); send(old);
        mvc.perform(get("/painel").session(session("ADMIN"))).andExpect(status().isOk())
            .andExpect(jsonPath("$.resumo.total").value(4)).andExpect(jsonPath("$.resumo.bloqueados").value(1))
            .andExpect(jsonPath("$.resumo.aprovados").value(1)).andExpect(jsonPath("$.resumo.liberadosSemInspecao").value(1))
            .andExpect(jsonPath("$.resumo.retidos").value(1)).andExpect(jsonPath("$.categoriasBloqueadas[0].quantidade").value(1))
            .andExpect(jsonPath("$.categoriasAtivas").isEmpty()).andExpect(jsonPath("$.politicaEfetivaConfirmada").value(false));
        String body=mvc.perform(get("/auditoria").session(session("ADMIN"))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("maskedSnippets","SENSITIVE-CONTENT-MUST-NOT-RETURN");
        assertThat(mapper.readTree(body).path("eventos")).hasSize(4);
    }
    @Test void endpointFilterAndJustificationsStayBoundToTheirOriginalEndpoint() throws Exception {
        var target=event("ALVO","Blocked","File"); send(target); send(event("CONTROLE","Blocked","File"));
        var justification=Map.of("eventId",target.get("eventId"),"endpointId","ALVO","userName","synthetic", "occurredAtUtc",NOW.toString(),"justification","Literal <b>text</b>");
        mvc.perform(post("/agent/events").contentType("application/json").content(mapper.writeValueAsString(Map.of("overrides",List.of(justification)))))
            .andExpect(status().isOk());
        mvc.perform(get("/auditoria").param("endpoint","ALVO").session(session("ADMIN")))
            .andExpect(jsonPath("$.resumo.total").value(1)).andExpect(jsonPath("$.eventos[0].endpointId").value("ALVO"))
            .andExpect(jsonPath("$.justificativas[0].justification").value("Literal <b>text</b>"));
        mvc.perform(get("/auditoria").param("endpoint","INEXISTENTE").session(session("ADMIN")))
            .andExpect(jsonPath("$.resumo.total").value(0)).andExpect(jsonPath("$.justificativas").isEmpty());
    }
    @Test void heartbeatAgeAndActiveFlagControlOnlineWhileDuplicateNamesAreNotJoinedToAudits() throws Exception {
        jdbc.update("INSERT INTO hosts VALUES(1,'ALVO','Windows','11',?,1)",Timestamp.from(NOW.minusSeconds(10)));
        jdbc.update("INSERT INTO hosts VALUES(2,'DUPLICADO','Windows','10',?,1)",Timestamp.from(NOW.minusSeconds(200)));
        jdbc.update("INSERT INTO hosts VALUES(3,'DUPLICADO','Windows','10',?,0)",Timestamp.from(NOW.minusSeconds(10)));
        send(event("ALVO","Blocked","File")); send(event("DUPLICADO","Blocked","File"));
        mvc.perform(get("/endpoints").session(session("ADMIN"))).andExpect(status().isOk())
            .andExpect(jsonPath("$.resumo.total").value(3)).andExpect(jsonPath("$.resumo.online").value(1))
            .andExpect(jsonPath("$.itens[0].status").value("online")).andExpect(jsonPath("$.itens[0].inspecoes7d").value(1))
            .andExpect(jsonPath("$.itens[1].endpointId").value("host:2")).andExpect(jsonPath("$.itens[1].identityAmbiguous").value(true))
            .andExpect(jsonPath("$.itens[1].inspecoes7d").value(0));
        mvc.perform(get("/endpoints").param("q","ALVO").param("os","win11").param("status","online").session(session("ADMIN")))
            .andExpect(jsonPath("$.itens.length()").value(1)).andExpect(jsonPath("$.resumo.total").value(3));
    }
    @Test void filtersAreBoundedAndSqlFailureIsNeverAnEmptySuccess() throws Exception {
        mvc.perform(get("/auditoria").param("endpoint","x".repeat(256)).session(session("ADMIN"))).andExpect(status().isBadRequest());
        mvc.perform(get("/endpoints").param("status","invalid").session(session("ADMIN"))).andExpect(status().isBadRequest());
        jdbc.execute("DROP TABLE agent_audit_ingest");
        mvc.perform(get("/painel").session(session("ADMIN"))).andExpect(status().is5xxServerError());
    }
    @Test void statisticsCrossPagesAndTheResponseDeclaresTruncation() throws Exception {
        var store=new AgentEventsStore(source,mapper);
        for (int i=0;i<1001;i++) store.accept(mapper.convertValue(Map.of("events",List.of(event("ALVO","Blocked","File"))),AuditContracts.Batch.class));
        mvc.perform(get("/auditoria").session(session("ADMIN"))).andExpect(status().isOk())
            .andExpect(jsonPath("$.resumo.total").value(1001)).andExpect(jsonPath("$.eventos.length()").value(1000))
            .andExpect(jsonPath("$.truncated").value(true));
    }
    @Test void endpointFiltersApplyBeforeThePageLimitAndTreatWildcardsAsText() throws Exception {
        for (int i=1;i<=1001;i++) jdbc.update("INSERT INTO hosts VALUES(?,?,'Windows','11',?,1)",i,"PC-"+i,Timestamp.from(NOW));
        mvc.perform(get("/endpoints").param("q","PC-1001").session(session("ADMIN")))
            .andExpect(jsonPath("$.itens.length()").value(1)).andExpect(jsonPath("$.itens[0].hostId").value(1001));
        mvc.perform(get("/endpoints").param("q","%").session(session("ADMIN"))).andExpect(jsonPath("$.itens").isEmpty());
    }
}
