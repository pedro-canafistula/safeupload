package com.safeupload.domain.entity;

import com.safeupload.application.dto.AgentContracts.Heartbeat;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "agent_endpoints")
public class Endpoint {
    @Id
    private String endpointId;
    private String hostname;
    @Column(length = 500)
    private String os;
    private String agentVersion;
    private int policyVersion;
    private Instant lastSeenUtc;

    protected Endpoint() {}

    public Endpoint(Heartbeat heartbeat, Instant receivedAt) {
        endpointId = heartbeat.endpointId();
        hostname = heartbeat.hostname();
        os = heartbeat.os();
        agentVersion = heartbeat.agentVersion();
        policyVersion = heartbeat.policyVersion();
        lastSeenUtc = receivedAt;
    }

    public String getEndpointId() { return endpointId; }
    public String getHostname() { return hostname; }
    public String getOs() { return os; }
    public String getAgentVersion() { return agentVersion; }
    public int getPolicyVersion() { return policyVersion; }
    public Instant getLastSeenUtc() { return lastSeenUtc; }
}
