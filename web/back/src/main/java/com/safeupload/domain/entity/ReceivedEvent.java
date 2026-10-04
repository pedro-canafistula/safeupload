package com.safeupload.domain.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "agent_events", indexes = @Index(name = "idx_agent_events_kind_time", columnList = "kind,occurredAtUtc"))
public class ReceivedEvent {
    @Id
    private String eventKey;
    @Column(nullable = false)
    private String kind;
    @Column(nullable = false)
    private Instant occurredAtUtc;
    @Lob
    @Column(nullable = false)
    private String payload;

    protected ReceivedEvent() {}

    public ReceivedEvent(String eventKey, String kind, Instant occurredAtUtc, String payload) {
        this.eventKey = eventKey;
        this.kind = kind;
        this.occurredAtUtc = occurredAtUtc;
        this.payload = payload;
    }

    public String getPayload() { return payload; }
}
