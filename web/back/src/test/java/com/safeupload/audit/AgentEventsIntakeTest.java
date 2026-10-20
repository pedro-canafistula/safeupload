package com.safeupload.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.safeupload.application.AgentService;
import com.safeupload.presentation.config.SecurityConfig;
import com.safeupload.presentation.controller.AgentController;
import com.safeupload.presentation.exception.ApiExceptionHandler;
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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.web.servlet.MockMvc;
import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real HTTP mapping, security chain and transactional SQL; no mocked persistence. */
@SpringBootTest(classes = AgentEventsIntakeTest.TestApp.class,
    properties = "spring.jackson.deserialization.fail-on-numbers-for-enums=true")
@AutoConfigureMockMvc
class AgentEventsIntakeTest {
    @SpringBootConfiguration
    @EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class,
        HibernateJpaAutoConfiguration.class, JpaRepositoriesAutoConfiguration.class})
    @Import({AgentEventsController.class, AgentEventsStore.class, SecurityConfig.class,
        ApiExceptionHandler.class, AgentController.class})
    static class TestApp {
        @Bean("appDataSource") DataSource dataSource() {
            String url = System.getenv("SAFEUPLOAD_AUDIT_TEST_DB_URL");
            return new DriverManagerDataSource(url == null
                ? "jdbc:h2:mem:audit-intake;MODE=MySQL;DB_CLOSE_DELAY=-1" : url,
                System.getenv().getOrDefault("SAFEUPLOAD_AUDIT_TEST_DB_USER", "sa"),
                System.getenv().getOrDefault("SAFEUPLOAD_AUDIT_TEST_DB_PASSWORD", ""));
        }
    }

    @MockBean AgentService currentService;
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired DataSource dataSource;
    JdbcTemplate jdbc;

    @BeforeEach void schema() throws Exception {
        jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("DROP TABLE IF EXISTS agent_audit_ingest");
        String ddl = Files.readString(Path.of("../../db/initdb/05_agent_audit_ingest.sql"));
        ddl = ddl.substring(ddl.indexOf("CREATE TABLE"));
        if (System.getenv("SAFEUPLOAD_AUDIT_TEST_DB_URL") == null) {
            ddl = ddl.replace("CHARACTER SET ascii COLLATE ascii_bin", "")
                .replace("ENGINE=InnoDB DEFAULT CHARSET=utf8mb4", "");
        }
        jdbc.execute(ddl);
    }

    ObjectNode event() {
        ObjectNode e = mapper.createObjectNode();
        e.put("eventId", UUID.randomUUID().toString());
        e.put("occurredAtUtc", "2026-10-20T17:15:00-03:00");
        e.put("endpointId", "PC-SINTETICO"); e.put("userName", "usuario-teste");
        e.put("fileName", "exemplo.txt"); e.put("extension", ".txt"); e.put("sizeBytes", 42);
        e.put("verdict", "Blocked"); e.putArray("categories").add("Cpf");
        e.put("processName", "explorer.exe"); e.put("processId", 123);
        e.put("destinationPath", "E:\\Destino"); e.put("policyVersion", 7); e.put("elapsedMs", 15);
        return e;
    }

    String batch(Object... events) throws Exception {
        return mapper.writeValueAsString(Map.of("schemaVersion", 1, "hostname", "PC-SINTETICO",
            "agentVersion", "0.1.1", "events", List.of(events), "overrides", List.of()));
    }
    int count() { return jdbc.queryForObject("SELECT COUNT(*) FROM agent_audit_ingest", Integer.class); }
    org.springframework.test.web.servlet.ResultActions send(String body) throws Exception {
        return mvc.perform(post("/agent/events").contentType("application/json").content(body));
    }

    @Test void acceptsMetadataAndAcknowledgesReplaysWithoutDuplicating() throws Exception {
        var e = event();
        e.putArray("maskedSnippets").add("SYNTHETIC-CONTENT-MUST-NOT-PERSIST");
        e.put("fileContent", "SYNTHETIC-CONTENT-MUST-NOT-PERSIST"); e.put("dispatched", false);
        send(batch(e)).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(1))
            .andExpect(jsonPath("$.acceptedOverrides").value(0));
        e.put("dispatched", true); e.put("occurredAtUtc", "2026-10-20T20:15:00Z");
        send(batch(e, e)).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(2));
        assertThat(count()).isEqualTo(1);
        String payload = jdbc.queryForObject("SELECT payload FROM agent_audit_ingest", String.class);
        assertThat(payload).doesNotContain("SYNTHETIC-CONTENT", "maskedSnippets", "dispatched", "fileNameValid");
        assertThat(mapper.readTree(payload).get("channel").asText()).isEqualTo("File");
    }

    @Test void conflictingEventRollsBackTheWholeBatch() throws Exception {
        var e = event(); send(batch(e)).andExpect(status().isOk());
        e.put("verdict", "Approved");
        send(batch(event(), e)).andExpect(status().isConflict());
        assertThat(count()).isEqualTo(1);
    }

    @Test void invalidBatchOrUnsupportedSchemaNeverPersistsPartialData() throws Exception {
        var e = event(); e.put("verdict", "not-a-verdict");
        send(batch(event(), e)).andExpect(status().isBadRequest());
        e = event(); e.put("sizeBytes", -1);
        send(batch(event(), e)).andExpect(status().isBadRequest());
        send(batch(event()).replace("\"schemaVersion\":1", "\"schemaVersion\":2"))
            .andExpect(status().isBadRequest());
        send("{\"events\":[null]}").andExpect(status().isBadRequest());
        assertThat(count()).isZero();
    }

    @Test void preservesDistinctJustificationsForOneEventAndDeduplicatesEach() throws Exception {
        var override = mapper.createObjectNode();
        override.put("eventId", event().get("eventId").asText());
        override.put("occurredAtUtc", "2026-10-20T20:16:00Z");
        override.put("endpointId", "PC-SINTETICO"); override.put("userName", "usuario-teste");
        override.put("justification", "Motivo sintético A");
        var second = override.deepCopy().put("justification", "Motivo sintético B");
        String body = mapper.writeValueAsString(Map.of("overrides", List.of(override, second)));
        send(body).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(0))
            .andExpect(jsonPath("$.acceptedOverrides").value(2));
        send(body).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedOverrides").value(2));
        assertThat(count()).isEqualTo(2);
    }

    @Test void acceptsClipboardWebRetainedAndLegacyEnvelope() throws Exception {
        var clipboard = event(); clipboard.put("channel", "Clipboard"); clipboard.put("fileName", "");
        var web = event(); web.put("channel", "Web"); web.put("verdict", "Retained");
        String body = mapper.writeValueAsString(Map.of("events", List.of(clipboard, web)));
        send(body).andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(2));
        send("{}").andExpect(status().isOk()).andExpect(jsonPath("$.acceptedEvents").value(0))
            .andExpect(jsonPath("$.acceptedOverrides").value(0));
    }

    @Test void databaseFailureNeverAcknowledgesAndNewStoreReusesPersistedData() throws Exception {
        var e = event(); send(batch(e)).andExpect(status().isOk());
        var reopened = new AgentEventsStore(dataSource, mapper);
        var receipt = reopened.accept(mapper.readValue(batch(e), AuditContracts.Batch.class));
        assertThat(receipt.acceptedEvents()).isEqualTo(1); assertThat(count()).isEqualTo(1);
        jdbc.execute("DROP TABLE agent_audit_ingest");
        send(batch(event())).andExpect(status().is5xxServerError());
    }

    @Test void keepsTheExistingThiagoRoutesRegistered() throws Exception {
        mvc.perform(post("/agent/api/synchronize").contentType("application/json").content("{}"))
            .andExpect(status().isBadRequest());
        mvc.perform(post("/agent/api/heartbeat").contentType("application/json").content("{}"))
            .andExpect(status().isBadRequest());
    }
}
