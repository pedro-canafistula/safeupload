package com.safeupload.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

/** Leituras do painel, auditoria e endpoints. Tudo limitado à empresa do usuário (hosts.fk_id_empresa). */
@Service
public class AgentAdminQueries {
    private static final int PAGE = 500;
    private static final int LIMIT = 1000;
    public static final int ONLINE_SECONDS = 120;
    private static final String EXPECTED_POLICY = com.safeupload.policy.PolicyStore.EXPECTED_POLICY;
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

    /** Evento gravado + host autenticado que o enviou. */
    private ObjectNode document(String text, int hostId, String hostname) {
        try {
            var node = (ObjectNode) mapper.readTree(text);
            node.put("hostId", hostId);
            node.put("hostname", hostname);
            return node;
        } catch (JsonProcessingException | ClassCastException ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Registro de auditoria inválido.");
        }
    }

    private String where(Integer host) {
        return " FROM agent_audit_ingest a JOIN hosts h ON h.id_host = a.fk_id_host WHERE h.fk_id_empresa = ?" +
            " AND a.kind = ? AND a.occurred_at_utc >= ?" + (host == null ? "" : " AND a.fk_id_host = ?");
    }
    private Object[] arguments(int empresa, String kind, Integer host, Object... extra) {
        var args = new ArrayList<Object>(List.of(empresa, kind, since()));
        if (host != null) args.add(host);
        args.addAll(List.of(extra));
        return args.toArray();
    }

    private final class Totals {
        long total, blocked, approved, uninspected, retained;
        final Map<String, Long> categories = new LinkedHashMap<>();
        final Map<String, Long> days = new LinkedHashMap<>();
        Totals() {
            var today = LocalDate.ofInstant(clock.instant(), ZoneOffset.UTC);
            for (int ago = 6; ago >= 0; ago--) days.put(today.minusDays(ago).toString(), 0L);
        }
        void add(ObjectNode event) {
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

    // Páginas por chave limitam a memória; as estatísticas cobrem a janela inteira de sete dias.
    private Totals totals(int empresa, Integer host) {
        var totals = new Totals();
        String after = "";
        while (true) {
            var rows = jdbc.query("SELECT a.record_key, a.payload, a.fk_id_host, h.hostname" + where(host) +
                " AND a.record_key > ? ORDER BY a.record_key LIMIT " + PAGE,
                (rs, n) -> Map.entry(rs.getString(1), document(rs.getString(2), rs.getInt(3), rs.getString(4))),
                arguments(empresa, "audit", host, after));
            for (var row : rows) totals.add(row.getValue());
            if (rows.size() < PAGE) return totals;
            after = rows.getLast().getKey();
        }
    }

    private List<ObjectNode> rows(int empresa, String kind, Integer host, int limit) {
        return jdbc.query("SELECT a.payload, a.fk_id_host, h.hostname" + where(host) +
            " ORDER BY a.occurred_at_utc DESC, a.record_key LIMIT " + limit,
            (rs, n) -> document(rs.getString(1), rs.getInt(2), rs.getString(3)), arguments(empresa, kind, host));
    }

    public static String categoryName(String key) {
        return switch (key) {
            case "Cpf" -> "CPF"; case "Cnpj" -> "CNPJ"; case "PaymentCard" -> "Cartão de pagamento";
            case "Password" -> "Senha em texto claro"; case "Secret" -> "Segredo/credencial";
            case "Rg" -> "RG"; case "BankData" -> "Dados bancários"; case "HealthData" -> "Dados de saúde";
            case "ConfidentialDocument" -> "Documento confidencial"; case "PersonalData" -> "Dados pessoais"; default -> key;
        };
    }

    public Map<String, Object> dashboard(int empresa) { return read(() -> {
        var totals = totals(empresa, null);
        var trend = totals.days.entrySet().stream().map(e -> Map.of("data", e.getKey(), "quantidade", e.getValue())).toList();
        var categories = totals.categories.entrySet().stream().map(e -> Map.of(
            "codigo", e.getKey(), "nome", categoryName(e.getKey()), "quantidade", e.getValue())).toList();
        var defaults = jdbc.query("""
            SELECT p.id_politica, p.nome, (SELECT MAX(id_versao) FROM politica_versoes v WHERE v.fk_id_politica = p.id_politica)
            FROM politicas p WHERE p.fk_id_empresa = ? AND p.padrao = 1""",
            (rs, n) -> Map.of("id", rs.getInt(1), "nome", rs.getString(2), "versao", rs.getInt(3)), empresa);
        var machines = endpointRows(empresa, "all", "");
        long online = machines.stream().filter(m -> m.get("status").equals("online")).count();
        long outdated = machines.stream().filter(m -> Boolean.TRUE.equals(m.get("politicaDesatualizada"))).count();
        var result = new LinkedHashMap<String, Object>();
        result.put("periodo", "Últimos 7 dias (UTC)");
        result.put("resumo", totals.summary());
        result.put("tendencia", trend);
        result.put("categoriasBloqueadas", categories);
        result.put("recentes", rows(empresa, "audit", null, 6));
        result.put("politicaPadrao", defaults.isEmpty() ? null : defaults.getFirst());
        result.put("maquinas", Map.of("total", machines.size(), "online", online, "politicaDesatualizada", outdated));
        return result;
    }); }

    public Map<String, Object> audit(int empresa, Integer host) {
        return read(() -> {
            var totals = totals(empresa, host);
            var events = rows(empresa, "audit", host, LIMIT);
            var result = new LinkedHashMap<String, Object>();
            result.put("resumo", totals.summary());
            result.put("eventos", events);
            result.put("host", host);
            result.put("justificativas", rows(empresa, "override", host, LIMIT));
            result.put("limit", LIMIT);
            result.put("truncated", totals.total > events.size());
            return result;
        });
    }

    /** CSV dos últimos 7 dias (UTF-8 com BOM, separador ";", para abrir direto no Excel). */
    public String exportCsv(int empresa, Integer host) {
        var events = read(() -> rows(empresa, "audit", host, 100_000));
        var csv = new StringBuilder("﻿");
        csv.append("data_utc;maquina;usuario;canal;arquivo;tamanho_bytes;resultado;categorias;processo;destino;versao_politica;motivo_nao_inspecao\r\n");
        for (var event : events) {
            var categories = new ArrayList<String>();
            event.path("categories").forEach(c -> categories.add(categoryName(c.asText())));
            csv.append(String.join(";", List.of(
                cell(event.path("occurredAtUtc").asText()), cell(event.path("hostname").asText()),
                cell(event.path("userName").asText()), cell(event.path("channel").asText()),
                cell(event.path("fileName").asText()), cell(event.path("sizeBytes").asText()),
                cell(verdictName(event.path("verdict").asText())), cell(String.join(", ", categories)),
                cell(event.path("processName").asText()), cell(event.path("destinationPath").asText()),
                cell(event.path("policyVersion").asText()), cell(event.path("notInspectedReason").asText(""))))).append("\r\n");
        }
        return csv.toString();
    }

    private static String verdictName(String verdict) {
        return switch (verdict) {
            case "Blocked" -> "Bloqueado"; case "Approved" -> "Aprovado";
            case "AllowedWithoutInspection" -> "Liberado sem inspeção"; case "Retained" -> "Retido"; default -> verdict;
        };
    }

    /** Aspas sempre; prefixo ' em células que o Excel interpretaria como fórmula. */
    private static String cell(String value) {
        String text = value == null ? "" : value;
        if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) text = "'" + text;
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    public Map<String, Object> endpoints(int empresa, String status, String q) {
        if (q == null || q.length() > 100 || q.chars().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filtro inválido.");
        if (!List.of("all", "online", "offline", "revogado").contains(status))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Filtro inválido.");
        return read(() -> {
            var all = endpointRows(empresa, "all", "");
            var items = endpointRows(empresa, status, q);
            long online = all.stream().filter(m -> m.get("status").equals("online")).count();
            long revoked = all.stream().filter(m -> m.get("status").equals("revogado")).count();
            return Map.of("resumo", Map.of("total", all.size(), "online", online, "offline", all.size() - online - revoked,
                    "revogados", revoked),
                "itens", items.size() > LIMIT ? items.subList(0, LIMIT) : items,
                "onlineThresholdSeconds", ONLINE_SECONDS, "limit", LIMIT, "truncated", items.size() > LIMIT);
        });
    }

    private List<Map<String, Object>> endpointRows(int empresa, String status, String q) {
        Instant now = clock.instant();
        var args = new ArrayList<Object>(List.of(since(), empresa));
        String filter = "";
        if (!q.isEmpty()) {
            filter = " AND LOWER(CONCAT(COALESCE(h.hostname,''),' ',COALESCE(h.ip,''),' host:',h.id_host)) LIKE ? ESCAPE '!'";
            args.add("%" + q.toLowerCase(Locale.ROOT).replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%");
        }
        List<Map<String, Object>> rows = jdbc.query("""
            SELECT h.id_host, h.hostname, h.ip, h.sistema_operacional, h.versao_so, h.versao_agente, h.politica_aplicada,
                   h.visto_por_ultimo, h.revogado_em, g.id_grupo, g.nome grupo, e.id_politica, e.nome politica, e.versao,
                   (SELECT COUNT(*) FROM agent_audit_ingest a WHERE a.fk_id_host = h.id_host AND a.kind = 'audit'
                      AND a.occurred_at_utc >= ?) inspecoes
            FROM hosts h
            LEFT JOIN grupos g ON g.id_grupo = h.fk_id_grupo
            LEFT JOIN (SELECT p.id_politica, p.nome, MAX(v.id_versao) versao FROM politicas p
                       JOIN politica_versoes v ON v.fk_id_politica = p.id_politica GROUP BY p.id_politica, p.nome) e
              ON e.id_politica = """ + EXPECTED_POLICY + """

            WHERE h.fk_id_empresa = ?""" + filter + " ORDER BY h.hostname, h.id_host", (rs, n) -> {
            Timestamp seen = rs.getTimestamp("visto_por_ultimo");
            long age = seen == null ? Long.MAX_VALUE : Duration.between(seen.toInstant(), now).getSeconds();
            String state = rs.getTimestamp("revogado_em") != null ? "revogado"
                : age >= -5 && age <= ONLINE_SECONDS ? "online" : "offline";
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("hostId", rs.getInt("id_host"));
            row.put("hostname", rs.getString("hostname"));
            row.put("ip", rs.getString("ip"));
            row.put("os", String.join(" ", java.util.Objects.toString(rs.getString("sistema_operacional"), ""),
                java.util.Objects.toString(rs.getString("versao_so"), "")).trim());
            row.put("agentVersion", rs.getString("versao_agente"));
            row.put("grupo", rs.getObject("id_grupo") == null ? null
                : Map.of("id", rs.getInt("id_grupo"), "nome", rs.getString("grupo")));
            Integer expected = rs.getObject("id_politica") == null ? null : rs.getInt("versao");
            row.put("politicaEsperada", expected == null ? null
                : Map.of("id", rs.getInt("id_politica"), "nome", rs.getString("politica"), "versao", expected));
            Integer applied = (Integer) rs.getObject("politica_aplicada");
            row.put("politicaAplicada", applied);
            row.put("politicaDesatualizada", expected != null && !expected.equals(applied));
            row.put("lastSeenUtc", seen == null ? null : seen.toInstant().toString());
            row.put("status", state);
            row.put("inspecoes7d", rs.getLong("inspecoes"));
            return row;
        }, args.toArray());
        return status.equals("all") ? rows : rows.stream().filter(r -> r.get("status").equals(status)).toList();
    }
}
