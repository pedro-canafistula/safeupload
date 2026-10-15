package com.safeupload.application.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

public final class AgentContracts {

    private AgentContracts() {
    }

    public enum Verdict {
        Approved,
        Blocked,
        AllowedWithoutInspection,
        Retained
    }

    public enum Category {
        Cpf,
        Cnpj,
        PaymentCard,
        Password,
        Secret
    }

    public enum AuditChannel {
        File,
        Clipboard,
        Web
    }

    public enum ClipboardMode {
        Off,
        Audit,
        Block
    }

    public record Heartbeat(
            @NotBlank @Size(max = 255) String endpointId,
            @NotBlank @Size(max = 255) String hostname,
            @NotBlank @Size(max = 500) String os,
            @NotBlank @Size(max = 100) String agentVersion,
            @NotNull @Positive Integer policyVersion
    ) {
    }

    public record HeartbeatResponse(
            String endpointId,
            OffsetDateTime serverTimeUtc,
            int policyVersion
    ) {
    }

    public record AuditEvent(
            @NotNull UUID eventId,
            @NotNull OffsetDateTime occurredAtUtc,
            @NotBlank @Size(max = 255) String endpointId,
            @NotBlank String userName,
            @NotNull @Size(max = 255) String fileName,
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
            boolean dispatched,
            AuditChannel channel,
            @jakarta.validation.constraints.Pattern(regexp = "[0-9a-fA-F]{64}") String publishedSha256Hex
    ) {

        public AuditEvent {
            categories = categories == null
                    ? List.of()
                    : List.copyOf(categories);

            maskedSnippets = maskedSnippets == null
                    ? List.of()
                    : List.copyOf(maskedSnippets);

            if (occurredAtUtc != null) {
                occurredAtUtc = occurredAtUtc.withOffsetSameInstant(ZoneOffset.UTC);
            }

            channel = channel == null
                    ? AuditChannel.File
                    : channel;
        }

        @AssertTrue(message = "fileName é obrigatório para eventos do canal File")
        public boolean isFileNameValid() {
            return channel != AuditChannel.File
                    || (fileName != null && !fileName.isBlank());
        }

        /*
         * Compatibilidade com o código Java anterior ao campo channel.
         * Eventos criados pelo construtor antigo são tratados como File.
         */
        public AuditEvent(
                UUID eventId,
                OffsetDateTime occurredAtUtc,
                String endpointId,
                String userName,
                String fileName,
                String extension,
                Long sizeBytes,
                Verdict verdict,
                List<Category> categories,
                List<String> maskedSnippets,
                String processName,
                Integer processId,
                String destinationPath,
                String notInspectedReason,
                Integer policyVersion,
                Long elapsedMs,
                boolean dispatched
        ) {
            this(
                    eventId,
                    occurredAtUtc,
                    endpointId,
                    userName,
                    fileName,
                    extension,
                    sizeBytes,
                    verdict,
                    categories,
                    maskedSnippets,
                    processName,
                    processId,
                    destinationPath,
                    notInspectedReason,
                    policyVersion,
                    elapsedMs,
                    dispatched,
                    AuditChannel.File,
                    null
            );
        }
    }

    public record OverrideEvent(
            @NotNull UUID eventId,
            @NotBlank String justification,
            @NotNull OffsetDateTime occurredAtUtc,
            @NotBlank String userName,
            @NotBlank @Size(max = 255) String endpointId
    ) {

        public OverrideEvent {
            if (occurredAtUtc != null) {
                occurredAtUtc = occurredAtUtc.withOffsetSameInstant(ZoneOffset.UTC);
            }
        }
    }

    public record SubmitEvents(
            @Size(max = 100)
            List<@NotNull @Valid AuditEvent> events,

            @Size(max = 100)
            List<@NotNull @Valid OverrideEvent> overrides
    ) {

        public SubmitEvents {
            events = events == null
                    ? List.of()
                    : List.copyOf(events);

            overrides = overrides == null
                    ? List.of()
                    : List.copyOf(overrides);
        }
    }

    public record SubmitResponse(
            int acceptedEvents,
            int acceptedOverrides
    ) {
    }

    public record MonitoredScopes(
            List<String> extensions,
            List<String> destinationPaths,
            List<String> sourcePaths,
            boolean removableDrives,
            boolean networkPaths
    ) {
    }

    public record Clipboard(
            ClipboardMode mode,
            List<String> egressDestinations,
            List<String> excludedSources,
            int maxTextLength,
            boolean oversizedTextIsDirty
    ) {
    }

    public record Policy(
            int version,
            List<Category> activeCategories,
            MonitoredScopes monitoredScopes,
            int maxFileSizeMb,
            int inspectionTimeoutSeconds,
            boolean auditOnly,
            boolean overrideAllowed,
            boolean failOpen,
            List<String> excludedProcesses,
            Clipboard clipboard
    ) {
    }
}
