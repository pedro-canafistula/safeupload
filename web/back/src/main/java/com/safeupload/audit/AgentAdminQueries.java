package com.safeupload.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Reads persisted intake metadata; never changes registration, policy or queue acknowledgements. */
@Service
public class AgentAdminQueries {
    private static final int PAGE = 500;
    private static final int LIMIT = 1000;
    private static final int ONLINE_SECONDS = 120;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final TransactionTemplate snapshot;

    public AgentAdminQueries(@Qualifier("appDataSource") DataSource source, ObjectMapper mapper, Clock clock) {
        this.jdbc = new JdbcTemplate(source);
        this.mapper = mapper;
        this.clock = clock;
        this.snapshot = new TransactionTemplate(new DataSourceTransactionManager(source));
        this.snapshot.setReadOnly(true);
        this.snapshot.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    private <T> T read(Supplier<T> action) { return snapshot.execute(ignored -> action.get()); }
    private Timestamp since() { return Timestamp.from(LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC)
        .minusDays(6).atStartOfDay(ZoneOffset.UTC).toInstant()); }
    private JsonNode document(String text) {
        try { return mapper.readTree(text); }
        catch (JsonProcessingException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Registro de auditoria inválido.");
        }
    }
    private void bounded(String text) {
        if (text == null || text.length() > 255 || text.chars().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filtro inválido.");
    }
    private String where(String endpoint) { return "kind='audit' AND occurred_at_utc >= ?" +
        (endpoint.isEmpty() ? "" : " AND endpoint_id = ?"); }
    private List<Object> arguments(String endpoint) {
        var args = new ArrayList<Object>(); args.add(since());
        if (!endpoint.isEmpty()) args.add(endpoint);
        return args;
    }

    private final class Totals {
        long total, blocked, approved, uninspected, retained;
        final Map<String, Long> categories = new LinkedHashMap<>();
        final Map<String, Long> days = new LinkedHashMap<>();
        Totals() {
            var today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
            for (int ago = 6; ago >= 0; ago--) days.put(today.minusDays(ago).toString(), 0L);
        }
        void add(JsonNode event) {
            total++;
            String verdict = event.path("verdict").asText();
            switch (verdict) {
                case "Blocked" -> blocked++;
                case "Approved" -> approved++;
                case "AllowedWithoutInspection" -> uninspected++;
                case "Retained" -> retained++;
                default -> throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Resultado de auditoria inválido.");
            }
            for (var category : event.path("categories")) {
                if (verdict.equals("Blocked")) categories.merge(category.asText(), 1L, Long::sum);
            }
            var day = Instant.parse(event.path("occurredAtUtc").asText()).atOffset(ZoneOffset.UTC).toLocalDate().toString();
            if (days.containsKey(day)) days.merge(day, 1L, Long::sum);
        }
        Map<String, Object> summary() { return Map.of("total", total, "bloqueados", blocked,
            "aprovados", approved, "liberadosSemInspecao", uninspected, "retidos", retained); }
    }

    // Keyset pages bound the in-memory data while statistics cover the complete seven-day window.
    private Totals totals(String endpoint) {
        var totals = new Totals();
        String after = "";
        while (true) {
            var args = arguments(endpoint); args.add(after);
            var rows = jdbc.queryForList("SELECT record_key,payload FROM agent_audit_ingest WHERE " +
                where(endpoint) + " AND record_key > ? ORDER BY record_key LIMIT " + PAGE, args.toArray());
            for (var row : rows) totals.add(document((String)row.get("payload")));
            if (rows.size() < PAGE) return totals;
            after = (String)rows.getLast().get("record_key");
        }
    }
    private List<JsonNode> events(String endpoint, int limit) {
        return jdbc.query("SELECT payload FROM agent_audit_ingest WHERE " + where(endpoint) +
            " ORDER BY occurred_at_utc DESC,record_key LIMIT " + limit,
            (rs, number) -> document(rs.getString(1)), arguments(endpoint).toArray());
    }
    private String categoryName(String key) {
        return switch (key) {
            case "Cpf" -> "CPF"; case "Cnpj" -> "CNPJ"; case "PaymentCard" -> "Cartão de pagamento";
            case "Password" -> "Senha em texto claro"; case "Secret" -> "Segredo/credencial"; default -> key;
        };
    }
    public Map<String, Object> dashboard() { return read(() -> {
        var totals = totals("");
        var trend = totals.days.entrySet().stream().map(e -> Map.of("data", e.getKey(), "quantidade", e.getValue())).toList();
        var categories = totals.categories.entrySet().stream().map(e -> Map.of(
            "codigo", e.getKey(), "nome", categoryName(e.getKey()), "quantidade", e.getValue())).toList();
        // Observed categories are not proof of the policy currently applied by an agent.
        return Map.of("periodo", "Últimos 7 dias (UTC)", "resumo", totals.summary(), "tendencia", trend,
            "categoriasBloqueadas", categories, "recentes", events("", 6), "categoriasAtivas", List.of(), "politicaEfetivaConfirmada", false);
    }); }
    public Map<String, Object> audit(String endpoint) {
        bounded(endpoint);
        return read(() -> {
            var totals = totals(endpoint);
            var rows = events(endpoint, LIMIT);
            var args = arguments(endpoint);
            var overrides = jdbc.query("SELECT payload FROM agent_audit_ingest WHERE kind='override' AND occurred_at_utc >= ?" +
                (endpoint.isEmpty() ? "" : " AND endpoint_id = ?") + " ORDER BY occurred_at_utc DESC,record_key LIMIT " + LIMIT,
                (rs, number) -> document(rs.getString(1)), args.toArray());
            return Map.of("resumo", totals.summary(), "eventos", rows, "endpoint", endpoint,
                "justificativas", overrides, "limit", LIMIT, "truncated", totals.total > rows.size());
        });
    }
    public Map<String, Object> endpoints(String status, String os, String q) {
        bounded(q);
        if (!List.of("all", "online", "offline").contains(status) || !List.of("all", "win10", "win11", "other").contains(os))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filtro inválido.");
        return read(() -> {
            Instant now = clock.instant();
            var filter = new StringBuilder(" WHERE 1=1");
            var args = new ArrayList<Object>();
            if (!status.equals("all")) {
                filter.append(" AND CASE WHEN h.ativo=1 AND h.visto_por_ultimo>=? AND h.visto_por_ultimo<=? THEN 'online' ELSE 'offline' END=?");
                args.add(Timestamp.from(now.minusSeconds(ONLINE_SECONDS))); args.add(Timestamp.from(now.plusSeconds(5))); args.add(status);
            }
            String systemText = "LOWER(CONCAT(COALESCE(h.sistema_operacional,''),' ',COALESCE(h.versao_so,'')))";
            if (os.equals("win10")) filter.append(" AND " + systemText + " LIKE '%windows 10%'");
            if (os.equals("win11")) filter.append(" AND " + systemText + " LIKE '%windows 11%'");
            if (os.equals("other")) filter.append(" AND " + systemText + " NOT LIKE '%windows 10%' AND " + systemText + " NOT LIKE '%windows 11%'");
            if (!q.isEmpty()) {
                filter.append(" AND LOWER(CONCAT(COALESCE(h.hostname,''),' host:',h.id_host)) LIKE ? ESCAPE '!'");
                args.add("%" + q.toLowerCase(Locale.ROOT).replace("!","!!").replace("%","!%").replace("_","!_") + "%");
            }
            var all = jdbc.query("SELECT h.id_host,h.hostname,h.sistema_operacional,h.versao_so,h.visto_por_ultimo,h.ativo," +
                "(SELECT COUNT(*) FROM hosts n WHERE n.hostname=h.hostname) name_count FROM hosts h" + filter + " ORDER BY h.id_host LIMIT " + LIMIT,
                (rs, number) -> {
                    int id = rs.getInt("id_host");
                    String hostname = rs.getString("hostname");
                    boolean ambiguous = hostname == null || hostname.isBlank() || rs.getInt("name_count") != 1;
                    String endpoint = ambiguous ? "host:" + id : hostname;
                    Timestamp seen = rs.getTimestamp("visto_por_ultimo");
                    long age = seen == null ? Long.MAX_VALUE : Duration.between(seen.toInstant(), now).getSeconds();
                    String state = rs.getInt("ativo") == 1 && age >= -5 && age <= ONLINE_SECONDS ? "online" : "offline";
                    String system = String.join(" ", java.util.Objects.toString(rs.getString("sistema_operacional"), ""),
                        java.util.Objects.toString(rs.getString("versao_so"), "")).trim();
                    var latest = ambiguous ? List.<Map<String,Object>>of() : jdbc.queryForList(
                        "SELECT agent_version,payload FROM agent_audit_ingest WHERE kind='audit' AND endpoint_id=? ORDER BY occurred_at_utc DESC,record_key LIMIT 1", endpoint);
                    var row = new LinkedHashMap<String,Object>();
                    row.put("endpointId", endpoint); row.put("hostId", id); row.put("identityAmbiguous", ambiguous);
                    row.put("hostname", hostname == null ? endpoint : hostname); row.put("os", system);
                    row.put("agentVersion", latest.isEmpty() || latest.getFirst().get("agent_version") == null ? "Não informado" : latest.getFirst().get("agent_version"));
                    row.put("policyVersion", latest.isEmpty() ? null : document((String)latest.getFirst().get("payload")).path("policyVersion").asInt());
                    row.put("lastSeenUtc", seen == null ? null : seen.toInstant().toString()); row.put("status", state);
                    row.put("inspecoes7d", ambiguous ? 0L : jdbc.queryForObject("SELECT COUNT(*) FROM agent_audit_ingest WHERE kind='audit' AND endpoint_id=? AND occurred_at_utc>=?", Long.class, endpoint, since()));
                    return row;
                }, args.toArray());
            long total = jdbc.queryForObject("SELECT COUNT(*) FROM hosts", Long.class);
            long online = jdbc.queryForObject("SELECT COUNT(*) FROM hosts WHERE ativo=1 AND visto_por_ultimo>=? AND visto_por_ultimo<=?", Long.class,
                Timestamp.from(now.minusSeconds(ONLINE_SECONDS)), Timestamp.from(now.plusSeconds(5)));
            long filtered = jdbc.queryForObject("SELECT COUNT(*) FROM hosts h" + filter, Long.class, args.toArray());
            return Map.of("resumo", Map.of("total", total, "online", online, "offline", total-online),
                "itens", all, "onlineThresholdSeconds", ONLINE_SECONDS, "limit", LIMIT, "truncated", filtered > all.size());
        });
    }
}
