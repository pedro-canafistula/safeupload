package com.safeupload.audit;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

public final class AuditContracts {
    private AuditContracts() {}
    public enum Verdict { Approved, Blocked, AllowedWithoutInspection, Retained }
    public enum Category { Cpf, Cnpj, PaymentCard, Password, Secret }
    public enum Channel { File, Clipboard, Web }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Batch(
        @Min(1) @Max(1) Integer schemaVersion,
        @Size(max = 255) String hostname,
        @Size(max = 200) String agentVersion,
        @Size(max = 100) List<@NotNull @Valid Event> events,
        @Size(max = 100) List<@NotNull @Valid Override> overrides
    ) {
        public Batch {
            events = events == null ? List.of() : events;
            overrides = overrides == null ? List.of() : overrides;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Event(
        @NotNull UUID eventId,
        @NotNull OffsetDateTime occurredAtUtc,
        @NotBlank @Size(max = 255) String endpointId,
        @NotBlank @Size(max = 1000) String userName,
        @NotNull @Size(max = 255) String fileName,
        @NotNull @Size(max = 100) String extension,
        @NotNull @PositiveOrZero Long sizeBytes,
        @NotNull Verdict verdict,
        @Size(max = 5) List<@NotNull Category> categories,
        @NotNull @Size(max = 1000) String processName,
        @NotNull @PositiveOrZero Integer processId,
        @NotNull @Size(max = 4096) String destinationPath,
        @Size(max = 1000) String notInspectedReason,
        @NotNull @Positive Integer policyVersion,
        @NotNull @PositiveOrZero Long elapsedMs,
        Channel channel,
        @Pattern(regexp = "[0-9a-fA-F]{64}") String publishedSha256Hex
    ) {
        public Event {
            occurredAtUtc = utc(occurredAtUtc);
            categories = categories == null ? List.of() : categories;
            channel = channel == null ? Channel.File : channel;
        }
        @AssertTrue(message = "fileName obrigatório no canal File")
        public boolean isFileNameValid() {
            return channel != Channel.File || (fileName != null && !fileName.isBlank());
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Override(
        @NotNull UUID eventId,
        @NotBlank @Size(max = 16000) String justification,
        @NotNull OffsetDateTime occurredAtUtc,
        @NotBlank @Size(max = 1000) String userName,
        @NotBlank @Size(max = 255) String endpointId
    ) {
        public Override { occurredAtUtc = utc(occurredAtUtc); }
    }

    public record Receipt(int acceptedEvents, int acceptedOverrides) {}
    private static OffsetDateTime utc(OffsetDateTime date) {
        return date == null ? null : date.withOffsetSameInstant(ZoneOffset.UTC);
    }
}
