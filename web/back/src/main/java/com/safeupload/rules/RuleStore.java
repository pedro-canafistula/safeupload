package com.safeupload.rules;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Regras personalizadas da empresa. Só regras compiladas e com exemplos conferidos são gravadas. */
@Service
public class RuleStore {
    public static final int MAX_RULES = 50;

    public record Stored(int id, String nome, String descricao, int revisao, RuleDefinition definicao) {}

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final Clock clock;

    public RuleStore(@Qualifier("appJdbc") JdbcTemplate jdbc, ObjectMapper mapper, Clock clock) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.clock = clock;
    }

    public List<Map<String, Object>> list(int empresa) {
        return jdbc.query("""
            SELECT id_regra, nome, descricao, definicao, revisao, atualizada_em, atualizada_por FROM regras_personalizadas
            WHERE fk_id_empresa = ? ORDER BY nome""", (rs, n) -> {
            var item = new LinkedHashMap<String, Object>();
            int id = rs.getInt("id_regra");
            item.put("id", id);
            item.put("nome", rs.getString("nome"));
            item.put("descricao", rs.getString("descricao"));
            item.put("revisao", rs.getInt("revisao"));
            item.put("quando", read(rs.getString("definicao")).quando());
            item.put("atualizadaEm", rs.getTimestamp("atualizada_em").toInstant().toString());
            item.put("atualizadaPor", rs.getString("atualizada_por"));
            item.put("politicas", policiesUsing(empresa, id));
            return item;
        }, empresa);
    }

    public Map<String, Object> get(int empresa, int id) {
        var stored = find(empresa, id);
        var item = new LinkedHashMap<String, Object>();
        item.put("id", stored.id());
        item.put("nome", stored.nome());
        item.put("descricao", stored.descricao());
        item.put("revisao", stored.revisao());
        item.put("quando", stored.definicao().quando());
        item.put("exemplos", stored.definicao().exemplos());
        item.put("politicas", policiesUsing(empresa, id));
        return item;
    }

    public Stored find(int empresa, int id) {
        var rows = jdbc.query("SELECT id_regra, nome, descricao, revisao, definicao FROM regras_personalizadas " +
                "WHERE id_regra = ? AND fk_id_empresa = ?",
            (rs, n) -> new Stored(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getInt(4), read(rs.getString(5))),
            id, empresa);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Regra não encontrada.");
        return rows.getFirst();
    }

    @Transactional("appTransactionManager")
    public Map<String, Object> create(int empresa, String user, String name, String description, RuleDefinition definition) {
        validate(definition);
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM regras_personalizadas WHERE fk_id_empresa = ?",
            Integer.class, empresa);
        if (count != null && count >= MAX_RULES) throw RuleDefinition.invalid("No máximo " + MAX_RULES + " regras por empresa.");
        var keys = new GeneratedKeyHolder();
        try {
            jdbc.update(connection -> {
                var statement = connection.prepareStatement("""
                    INSERT INTO regras_personalizadas (fk_id_empresa, nome, descricao, definicao, revisao, atualizada_em, atualizada_por)
                    VALUES (?,?,?,?,1,?,?)""", java.sql.Statement.RETURN_GENERATED_KEYS);
                statement.setInt(1, empresa);
                statement.setString(2, name(name));
                statement.setString(3, description(description));
                statement.setString(4, write(definition));
                statement.setTimestamp(5, Timestamp.from(clock.instant()));
                statement.setString(6, user);
                return statement;
            }, keys);
        } catch (DuplicateKeyException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Já existe uma regra com esse nome.");
        }
        return Map.of("id", keys.getKey().intValue(), "revisao", 1);
    }

    /** Edita a regra e cria uma versão nova de cada política que a usa, para os agentes buscarem a regra nova. */
    @Transactional("appTransactionManager")
    public Map<String, Object> update(int empresa, int id, String user, String name, String description,
                                      RuleDefinition definition, PolicyVersionBump bump) {
        validate(definition);
        var current = find(empresa, id);
        try {
            jdbc.update("""
                UPDATE regras_personalizadas SET nome = ?, descricao = ?, definicao = ?, revisao = revisao + 1,
                  atualizada_em = ?, atualizada_por = ? WHERE id_regra = ? AND fk_id_empresa = ?""",
                name(name), description(description), write(definition), Timestamp.from(clock.instant()), user, id, empresa);
        } catch (DuplicateKeyException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Já existe uma regra com esse nome.");
        }
        bump.bump(empresa, id, user + " (regra \"" + name(name) + "\" editada)");
        return Map.of("id", id, "revisao", current.revisao() + 1);
    }

    @Transactional("appTransactionManager")
    public void delete(int empresa, int id) {
        find(empresa, id);
        var using = policiesUsing(empresa, id);
        if (!using.isEmpty())
            throw new ResponseStatusException(HttpStatus.CONFLICT, "A regra é usada pelas políticas: " + String.join(", ", using) + ".");
        jdbc.update("DELETE FROM regras_personalizadas WHERE id_regra = ? AND fk_id_empresa = ?", id, empresa);
    }

    /** Avalia condições ainda não salvas sobre textos de teste (botão Testar). */
    public List<RuleDefinition.Evaluation> test(RuleDefinition.Condition when, List<String> texts) {
        if (texts == null || texts.isEmpty() || texts.size() > 10) throw RuleDefinition.invalid("Envie de 1 a 10 textos.");
        var compiled = new RuleDefinition(when, null).compile();
        return texts.stream().map(t -> {
            if (t == null || t.length() > 5000) throw RuleDefinition.invalid("Cada texto de teste tem até 5000 caracteres.");
            return compiled.evaluate(t);
        }).toList();
    }

    /** Nomes das políticas cuja versão atual usa a regra (com ação diferente de "ignorar"). */
    public List<String> policiesUsing(int empresa, int ruleId) {
        return jdbc.query("""
            SELECT p.nome, v.configuracao FROM politicas p JOIN politica_versoes v ON v.id_versao =
              (SELECT MAX(id_versao) FROM politica_versoes WHERE fk_id_politica = p.id_politica)
            WHERE p.fk_id_empresa = ? AND v.usa_regras = 1 ORDER BY p.nome""",
            (rs, n) -> usesRule(rs.getString(2), ruleId) ? rs.getString(1) : null, empresa)
            .stream().filter(java.util.Objects::nonNull).toList();
    }

    private boolean usesRule(String configuration, int ruleId) {
        try {
            var actions = mapper.readTree(configuration).path("regrasPersonalizadas");
            String action = actions.path(String.valueOf(ruleId)).asText("ignorar");
            return !action.equals("ignorar");
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void validate(RuleDefinition definition) {
        if (definition == null) throw RuleDefinition.invalid("Definição da regra obrigatória.");
        var compiled = definition.compile();
        definition.checkExamples(compiled);
    }

    private static String name(String name) {
        String value = name == null ? "" : name.strip();
        if (value.isEmpty() || value.length() > 80 || value.chars().anyMatch(Character::isISOControl))
            throw RuleDefinition.invalid("Nome obrigatório (até 80 caracteres).");
        return value;
    }

    private static String description(String description) {
        String value = description == null ? "" : description.strip();
        if (value.length() > 300) throw RuleDefinition.invalid("Descrição com até 300 caracteres.");
        return value.isEmpty() ? null : value;
    }

    private RuleDefinition read(String json) {
        try { return mapper.readValue(json, RuleDefinition.class); }
        catch (JsonProcessingException e) { throw new IllegalStateException("Regra gravada inválida.", e); }
    }

    private String write(RuleDefinition definition) {
        try { return mapper.writeValueAsString(definition); }
        catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    /** Implementado pelo PolicyStore: nova versão das políticas que usam a regra. */
    @FunctionalInterface
    public interface PolicyVersionBump {
        void bump(int empresa, int ruleId, String author);
    }
}
