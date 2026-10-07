package com.safeupload.application.dto;

import com.safeupload.application.dto.AgentContracts.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

public final class AdminViews {
    private AdminViews() {}

    public record Summary(long total, long bloqueados, long aprovados, long liberadosSemInspecao) {}
    public record Day(LocalDate data, long quantidade) {}
    public record CategoryCount(Category codigo, String nome, long quantidade) {}
    public record Dashboard(String periodo, Summary resumo, List<Day> tendencia,
            List<CategoryCount> categoriasBloqueadas, List<AuditEvent> recentes, List<Category> categoriasAtivas) {}
    public record Audit(Summary resumo, List<AuditEvent> eventos, String endpoint) {}
    public record EndpointSummary(long total, long online, long offline) {}
    public record EndpointRow(String endpointId, String hostname, String os, String agentVersion,
            int policyVersion, Instant lastSeenUtc, String status, long inspecoes7d) {}
    public record Endpoints(EndpointSummary resumo, List<EndpointRow> itens, int onlineThresholdSeconds) {}
}
