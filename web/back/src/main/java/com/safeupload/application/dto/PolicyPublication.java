package com.safeupload.application.dto;

import com.safeupload.application.dto.AgentContracts.Policy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.Instant;
import java.util.List;

public final class PolicyPublication {
    private PolicyPublication() {}

    // versao identifies the console schema; agent policy versions are allocated by the server.
    public record Request(
            @NotBlank @Pattern(regexp = "1\\.0") String versao,
            @NotBlank @Size(max = 120) String nome,
            @NotNull @Valid Destination destino,
            @NotBlank @Pattern(regexp = "bloquear", message = "Somente bloquear é suportado nesta versão do publicador.") String acao,
            @NotEmpty @Size(max = 9) List<@NotNull @Valid Rule> regras,
            Instant criadaEm,
            @NotBlank @Pattern(regexp = "console-administrativo") String origem) {}

    public record Destination(
            @NotBlank @Size(max = 255) String endpointId,
            @Null(message = "Use destino.endpointId selecionado no inventário; IP não identifica o agente.") String ip) {}
    public record Rule(@NotBlank @Size(max = 50) String tipo, @Size(max = 100) String nome) {}
    public record Published(String endpointId, String nome, int version, Instant publicadaEm, Policy policy) {}
}
