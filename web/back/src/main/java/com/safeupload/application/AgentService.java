package com.safeupload.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.domain.entity.Endpoint;
import com.safeupload.domain.entity.ReceivedEvent;
import com.safeupload.infrastructure.repository.EndpointRepository;
import com.safeupload.infrastructure.repository.ReceivedEventRepository;
import jakarta.persistence.EntityManager;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

@Service
public class AgentService {
    private final EndpointRepository endpoints;
    private final ReceivedEventRepository events;
    private final EntityManager entityManager;
    private final ObjectMapper mapper;
    private final Clock clock;

    public AgentService(EndpointRepository endpoints, ReceivedEventRepository events,
            EntityManager entityManager, ObjectMapper mapper, Clock clock) {
        this.endpoints = endpoints;
        this.events = events;
        this.entityManager = entityManager;
        this.mapper = mapper;
        this.clock = clock;
    }

    public Policy policy() {
        return new Policy(1, List.of(Category.values()),
                new MonitoredScopes(List.of(".txt", ".csv", ".docx", ".xlsx", ".pdf"),
                        List.of("C:\\SafeUpload\\Escopo Monitorado"), List.of(), true, true),
                20, 5, false, false, true, List.of("System", "SafeUpload.Agent.App"));
    }

    @Transactional
    public HeartbeatResponse heartbeat(Heartbeat heartbeat) {
        Instant now = clock.instant();
        endpoints.save(new Endpoint(heartbeat, now));
        return new HeartbeatResponse(heartbeat.endpointId(), OffsetDateTime.ofInstant(now, clock.getZone()), policy().version());
    }

    @Transactional
    public SubmitResponse submit(SubmitEvents batch) {
        for (AuditEvent event : batch.events()) {
            var document = mapper.valueToTree(event);
            ((com.fasterxml.jackson.databind.node.ObjectNode) document).remove("dispatched");
            store("audit:" + event.eventId(), "audit", event.occurredAtUtc().toInstant(), document.toString());
        }
        for (OverrideEvent event : batch.overrides()) {
            store("override:" + event.eventId(), "override", event.occurredAtUtc().toInstant(), mapper.valueToTree(event).toString());
        }
        entityManager.flush();
        return new SubmitResponse(batch.events().size(), batch.overrides().size());
    }

    private void store(String key, String kind, Instant occurredAt, String payload) {
        ReceivedEvent existing = entityManager.find(ReceivedEvent.class, key);
        if (existing != null) {
            if (!existing.getPayload().equals(payload)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Identificador de evento já recebido com outro conteúdo.");
            }
            return;
        }
        entityManager.persist(new ReceivedEvent(key, kind, occurredAt, payload));
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> auditEvents() {
        return events.findByKindOrderByOccurredAtUtcDescEventKeyAsc("audit").stream().map(stored -> {
            try {
                return mapper.readValue(stored.getPayload(), AuditEvent.class);
            } catch (JsonProcessingException exception) {
                throw new IllegalStateException("Evento armazenado inválido", exception);
            }
        }).toList();
    }

    @Transactional(readOnly = true)
    public List<Endpoint> endpoints() {
        return endpoints.findAllByOrderByLastSeenUtcDesc();
    }
}
