package com.safeupload.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import static org.springframework.http.HttpStatus.CONFLICT;

/** Append-only intake. Never changes host registration, policy or access tables. */
@Service
public class AgentEventsStore {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final ObjectMapper mapper;

    public AgentEventsStore(@Qualifier("appDataSource") DataSource dataSource, ObjectMapper mapper) {
        this.jdbc = new JdbcTemplate(dataSource);
        // Private manager: does not replace either of the application's JPA managers.
        this.transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.mapper = mapper;
    }

    public AuditContracts.Receipt accept(AuditContracts.Batch batch) {
        // execute() returns only after commit; a database failure never acknowledges a batch.
        return transaction.execute(status -> {
            for (var event : batch.events()) {
                ObjectNode document = mapper.valueToTree(event);
                document.remove("fileNameValid");
                String payload = document.toString();
                store("audit:" + event.eventId(), "audit", event.eventId().toString(),
                    event.endpointId(), event.occurredAtUtc().toInstant(), payload, batch);
            }
            for (var override : batch.overrides()) {
                String payload = json(override);
                // The agent can send several distinct justifications for the same event.
                store("override:" + sha256(payload), "override", override.eventId().toString(),
                    override.endpointId(), override.occurredAtUtc().toInstant(), payload, batch);
            }
            return new AuditContracts.Receipt(batch.events().size(), batch.overrides().size());
        });
    }

    private void store(String key, String kind, String eventId, String endpointId,
                       Instant occurredAt, String payload, AuditContracts.Batch batch) {
        var previous = jdbc.queryForList(
            "SELECT payload FROM agent_audit_ingest WHERE record_key = ?", String.class, key);
        if (!previous.isEmpty()) {
            if (!previous.getFirst().equals(payload)) {
                throw new ResponseStatusException(CONFLICT, "Evento já recebido com conteúdo diferente.");
            }
            return;
        }
        // The primary key also arbitrates concurrent requests. An insert race returns a
        // non-2xx through the existing exception handler; a subsequent retry is idempotent.
        jdbc.update("""
            INSERT INTO agent_audit_ingest
            (record_key, kind, event_id, endpoint_id, occurred_at_utc, received_at_utc,
             schema_version, sender_hostname, agent_version, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, key, kind, eventId, endpointId, Timestamp.from(occurredAt), Timestamp.from(Instant.now()),
            batch.schemaVersion() == null ? 1 : batch.schemaVersion(),
            batch.hostname(), batch.agentVersion(), payload);
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException exception) { throw new IllegalStateException(exception); }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
}
