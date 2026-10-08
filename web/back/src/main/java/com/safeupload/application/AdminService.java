package com.safeupload.application;

import com.safeupload.application.dto.AdminViews.*;
import com.safeupload.application.dto.AgentContracts.*;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class AdminService {
    private final AgentService agents;
    private final Clock clock;

    public AdminService(AgentService agents, Clock clock) {
        this.agents = agents;
        this.clock = clock;
    }

    public Dashboard dashboard() {
        Instant now = clock.instant();
        LocalDate firstDay = LocalDate.ofInstant(now, ZoneOffset.UTC).minusDays(6);
        List<AuditEvent> all = agents.auditEvents();
        List<AuditEvent> period = between(all, firstDay.atStartOfDay(ZoneOffset.UTC).toInstant(), now);
        Map<LocalDate, Long> daily = period.stream().collect(Collectors.groupingBy(
                event -> event.occurredAtUtc().toLocalDate(), Collectors.counting()));
        List<Day> trend = IntStream.range(0, 7).mapToObj(offset -> {
            LocalDate date = firstDay.plusDays(offset);
            return new Day(date, daily.getOrDefault(date, 0L));
        }).toList();
        Map<Category, Long> counts = period.stream().filter(event -> event.verdict() == Verdict.Blocked)
                .flatMap(event -> event.categories().stream().distinct())
                .collect(Collectors.groupingBy(category -> category, Collectors.counting()));
        List<CategoryCount> categories = counts.entrySet().stream()
                .map(entry -> new CategoryCount(entry.getKey(), categoryLabel(entry.getKey()), entry.getValue()))
                .sorted(Comparator.comparingLong(CategoryCount::quantidade).reversed().thenComparing(CategoryCount::nome))
                .toList();
        return new Dashboard("Últimos 7 dias (UTC)", summary(period), trend, categories,
                all.stream().limit(6).toList(), agents.policy().activeCategories());
    }

    public Audit audit(String endpoint) {
        String filter = endpoint == null ? "" : endpoint.trim();
        List<AuditEvent> events = agents.auditEvents().stream()
                .filter(event -> filter.isEmpty() || event.endpointId().equals(filter)).toList();
        return new Audit(summary(events), events, filter);
    }

    public Endpoints endpoints(String status, String os, String query) {
        Instant now = clock.instant();
        Map<String, Long> counts = between(agents.auditEvents(), now.minus(Duration.ofDays(7)), now).stream()
                .collect(Collectors.groupingBy(AuditEvent::endpointId, Collectors.counting()));
        List<EndpointRow> all = agents.endpoints().stream().map(endpoint -> new EndpointRow(
                endpoint.getEndpointId(), endpoint.getHostname(), endpoint.getOs(), endpoint.getAgentVersion(),
                endpoint.getPolicyVersion(), endpoint.getLastSeenUtc(),
                endpoint.getLastSeenUtc().isBefore(now.minusSeconds(90)) ? "offline" : "online",
                counts.getOrDefault(endpoint.getEndpointId(), 0L))).toList();
        long online = all.stream().filter(endpoint -> endpoint.status().equals("online")).count();
        String search = query.trim().toLowerCase(Locale.ROOT);
        List<EndpointRow> filtered = all.stream()
                .filter(endpoint -> !Set.of("online", "offline").contains(status) || endpoint.status().equals(status))
                .filter(endpoint -> !Set.of("win11", "win10", "other").contains(os) || osKind(endpoint.os()).equals(os))
                .filter(endpoint -> (endpoint.hostname() + " " + endpoint.endpointId()).toLowerCase(Locale.ROOT).contains(search))
                .toList();
        return new Endpoints(new EndpointSummary(all.size(), online, all.size() - online), filtered, 90);
    }

    private List<AuditEvent> between(List<AuditEvent> events, Instant start, Instant end) {
        return events.stream().filter(event -> !event.occurredAtUtc().toInstant().isBefore(start)
                && !event.occurredAtUtc().toInstant().isAfter(end)).toList();
    }

    private Summary summary(List<AuditEvent> events) {
        Map<Verdict, Long> counts = events.stream().collect(Collectors.groupingBy(AuditEvent::verdict, Collectors.counting()));
        return new Summary(events.size(), counts.getOrDefault(Verdict.Blocked, 0L),
                counts.getOrDefault(Verdict.Approved, 0L), counts.getOrDefault(Verdict.AllowedWithoutInspection, 0L));
    }

    private String osKind(String os) {
        String normalized = os.toLowerCase(Locale.ROOT);
        if (normalized.contains("windows 11")) return "win11";
        if (normalized.contains("windows 10")) return "win10";
        return "other";
    }

    private String categoryLabel(Category category) {
        return switch (category) {
            case Cpf -> "CPF";
            case Cnpj -> "CNPJ";
            case PaymentCard -> "Cartão de pagamento";
            case Password -> "Senha em texto claro";
            case Secret -> "Segredo/credencial";
        };
    }
}
