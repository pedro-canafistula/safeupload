package com.safeupload.domain.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "agent_published_policies")
public class PublishedPolicy {
    @Id @Column(length = 255)
    private String endpointId;
    @Column(nullable = false, length = 120)
    private String name;
    private int policyVersion;
    private Instant publishedAt;
    @Lob @Column(nullable = false)
    private String document;

    protected PublishedPolicy() {}
    public PublishedPolicy(String endpointId, String name, int policyVersion, Instant publishedAt, String document) {
        this.endpointId = endpointId;
        this.name = name;
        this.policyVersion = policyVersion;
        this.publishedAt = publishedAt;
        this.document = document;
    }
    public String getEndpointId() { return endpointId; }
    public String getName() { return name; }
    public int getPolicyVersion() { return policyVersion; }
    public Instant getPublishedAt() { return publishedAt; }
    public String getDocument() { return document; }
}
