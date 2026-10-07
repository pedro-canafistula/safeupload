package com.safeupload.application.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public final class AgentContracts {
    private AgentContracts() {}

    public enum Verdict { Approved, Blocked, AllowedWithoutInspection }
    public enum Category { Cpf, Cnpj, PaymentCard, Password, Secret }

    public record Heartbeat(
            @NotBlank @Size(max = 255) String endpointId,
            @NotBlank @Size(max = 255) String hostname,
            @NotBlank @Size(max = 500) String os,
            @NotBlank @Size(max = 100) String agentVersion,
            @NotNull @Positive Integer policyVersion) {}

    public record HeartbeatResponse(String endpointId, OffsetDateTime serverTimeUtc, int policyVersion) {}

    public record AuditEvent(
            @NotNull UUID eventId,
            @NotNull OffsetDateTime occurredAtUtc,
            @NotBlank @Size(max = 255) String endpointId,
            @NotBlank String userName,
            @NotBlank String fileName,
            @NotNull String extension,
            @NotNull @PositiveOrZero Long sizeBytes,
            @NotNull Verdict verdict,
            List<@NotNull Category> categories,
            List<@NotNull String> maskedSnippets,
            @NotNull String processName,
            @NotNull @PositiveOrZero Integer processId,
            @NotNull String destinationPath,
            String notInspectedReason,
            @NotNull @Positive Integer policyVersion,
            @NotNull @PositiveOrZero Long elapsedMs,
            boolean dispatched) {
        public AuditEvent {
            categories = categories == null ? List.of() : List.copyOf(categories);
            maskedSnippets = maskedSnippets == null ? List.of() : List.copyOf(maskedSnippets);
            if (occurredAtUtc != null) occurredAtUtc = occurredAtUtc.withOffsetSameInstant(java.time.ZoneOffset.UTC);
        }
    }

    public record OverrideEvent(
            @NotNull UUID eventId,
            @NotBlank String justification,
            @NotNull OffsetDateTime occurredAtUtc,
            @NotBlank String userName,
            @NotBlank @Size(max = 255) String endpointId) {
        public OverrideEvent {
            if (occurredAtUtc != null) occurredAtUtc = occurredAtUtc.withOffsetSameInstant(java.time.ZoneOffset.UTC);
        }
    }

    public record SubmitEvents(
            @Size(max = 100) List<@NotNull @Valid AuditEvent> events,
            @Size(max = 100) List<@NotNull @Valid OverrideEvent> overrides) {
        public SubmitEvents {
            events = events == null ? List.of() : List.copyOf(events);
            overrides = overrides == null ? List.of() : List.copyOf(overrides);
        }
    }

    public record SubmitResponse(int acceptedEvents, int acceptedOverrides) {}

    public record MonitoredScopes(List<String> extensions, List<String> destinationPaths,
            List<String> sourcePaths, boolean removableDrives, boolean networkPaths) {}

    public record Policy(int version, List<Category> activeCategories, MonitoredScopes monitoredScopes,
            int maxFileSizeMb, int inspectionTimeoutSeconds, boolean auditOnly,
            boolean overrideAllowed, boolean failOpen, List<String> excludedProcesses) {}
}
