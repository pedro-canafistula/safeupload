package com.safeupload.policy;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Políticas versionadas, grupos e a política padrão da empresa.
 * Política de um host = a do grupo; sem grupo (ou grupo sem política) = a padrão; sem padrão = nenhuma.
 */
@Service
public class PolicyStore {
    public record Effective(int idPolitica, String nome, int versao, PolicyConfig configuracao) {}

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final Clock clock;

    public PolicyStore(@Qualifier("appJdbc") JdbcTemplate jdbc, ObjectMapper mapper, Clock clock) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.clock = clock;
    }

    /** SQL da política esperada de cada host "h" (usado também pela tela Endpoints). */
    public static final String EXPECTED_POLICY = """
        COALESCE((SELECT g.fk_id_politica FROM grupos g WHERE g.id_grupo = h.fk_id_grupo),
                 (SELECT p.id_politica FROM politicas p WHERE p.fk_id_empresa = h.fk_id_empresa AND p.padrao = 1))""";

    public Optional<Effective> effectiveForHost(int hostId) {
        var rows = jdbc.query("SELECT p.id_politica, p.nome, v.id_versao, v.configuracao FROM hosts h " +
            "JOIN politicas p ON p.id_politica = " + EXPECTED_POLICY + " " +
            "JOIN politica_versoes v ON v.fk_id_politica = p.id_politica " +
            "WHERE h.id_host = ? ORDER BY v.id_versao DESC LIMIT 1",
            (rs, n) -> new Effective(rs.getInt(1), rs.getString(2), rs.getInt(3), read(rs.getString(4))), hostId);
        return rows.stream().findFirst();
    }

    // ---- políticas ----

    public List<Map<String, Object>> list(int empresa) {
        return jdbc.query("""
            SELECT p.id_politica, p.nome, p.padrao, v.id_versao, v.criada_em, v.criada_por,
              (SELECT GROUP_CONCAT(g.nome ORDER BY g.nome SEPARATOR '\u001f') FROM grupos g WHERE g.fk_id_politica = p.id_politica) grupos
            FROM politicas p JOIN politica_versoes v ON v.id_versao =
              (SELECT MAX(id_versao) FROM politica_versoes WHERE fk_id_politica = p.id_politica)
            WHERE p.fk_id_empresa = ? ORDER BY p.nome""", (rs, n) -> {
            var item = new LinkedHashMap<String, Object>();
            int id = rs.getInt("id_politica");
            item.put("id", id);
            item.put("nome", rs.getString("nome"));
            item.put("padrao", rs.getInt("padrao") == 1);
            item.put("versao", rs.getInt("id_versao"));
            item.put("atualizadaEm", rs.getTimestamp("criada_em").toInstant().toString());
            item.put("atualizadaPor", rs.getString("criada_por"));
            String groups = rs.getString("grupos");
            item.put("grupos", groups == null ? List.of() : List.of(groups.split("\u001f")));
            item.put("hosts", hostsUsing(empresa, id));
            return item;
        }, empresa);
    }

    private int hostsUsing(int empresa, int policyId) {
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM hosts h WHERE h.fk_id_empresa = ? AND h.revogado_em IS NULL AND "
            + EXPECTED_POLICY + " = ?", Integer.class, empresa, policyId);
        return count == null ? 0 : count;
    }

    public Map<String, Object> get(int empresa, int policyId) {
        var head = jdbc.queryForList("SELECT nome, padrao FROM politicas WHERE id_politica = ? AND fk_id_empresa = ?",
            policyId, empresa);
        if (head.isEmpty()) throw notFound("Política não encontrada.");
        var history = jdbc.queryForList("SELECT id_versao, configuracao, criada_em, criada_por FROM politica_versoes " +
            "WHERE fk_id_politica = ? ORDER BY id_versao DESC LIMIT 50", policyId);
        var item = new LinkedHashMap<String, Object>();
        item.put("id", policyId);
        item.put("nome", head.getFirst().get("nome"));
        item.put("padrao", ((Number) head.getFirst().get("padrao")).intValue() == 1);
        item.put("versao", history.getFirst().get("id_versao"));
        item.put("configuracao", read((String) history.getFirst().get("configuracao")));
        item.put("historico", history.stream().map(v -> Map.of(
            "versao", v.get("id_versao"),
            "criadaEm", ((Timestamp) v.get("criada_em")).toInstant().toString(),
            "criadaPor", v.get("criada_por"))).toList());
        return item;
    }

    @Transactional("appTransactionManager")
    public Map<String, Object> create(int empresa, String user, String name, boolean isDefault, PolicyConfig config) {
        String nome = name(name);
        var keys = new GeneratedKeyHolder();
        unique("Já existe uma política com esse nome.", () -> jdbc.update(connection -> {
            var statement = connection.prepareStatement(
                "INSERT INTO politicas (fk_id_empresa, nome, padrao) VALUES (?,?,0)", java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setInt(1, empresa);
            statement.setString(2, nome);
            return statement;
        }, keys));
        int id = keys.getKey().intValue();
        if (isDefault) makeDefault(empresa, id);
        return Map.of("id", id, "versao", addVersion(id, user, config));
    }

    @Transactional("appTransactionManager")
    public Map<String, Object> update(int empresa, int policyId, String user, String name, boolean isDefault, PolicyConfig config) {
        int changed = unique("Já existe uma política com esse nome.", () -> jdbc.update(
            "UPDATE politicas SET nome = ? WHERE id_politica = ? AND fk_id_empresa = ?", name(name), policyId, empresa));
        if (changed == 0) throw notFound("Política não encontrada.");
        if (isDefault) makeDefault(empresa, policyId);
        else jdbc.update("UPDATE politicas SET padrao = 0 WHERE id_politica = ?", policyId);
        return Map.of("id", policyId, "versao", addVersion(policyId, user, config));
    }

    @Transactional("appTransactionManager")
    public void delete(int empresa, int policyId) {
        var head = jdbc.queryForList("SELECT padrao FROM politicas WHERE id_politica = ? AND fk_id_empresa = ? FOR UPDATE",
            policyId, empresa);
        if (head.isEmpty()) throw notFound("Política não encontrada.");
        if (((Number) head.getFirst().get("padrao")).intValue() == 1)
            throw conflict("Esta é a política padrão; defina outra como padrão antes de excluir.");
        Integer groups = jdbc.queryForObject("SELECT COUNT(*) FROM grupos WHERE fk_id_politica = ?", Integer.class, policyId);
        if (groups != null && groups > 0) throw conflict("Há grupos usando esta política.");
        jdbc.update("DELETE FROM politicas WHERE id_politica = ?", policyId);
    }

    private void makeDefault(int empresa, int policyId) {
        jdbc.update("UPDATE politicas SET padrao = CASE WHEN id_politica = ? THEN 1 ELSE 0 END WHERE fk_id_empresa = ?",
            policyId, empresa);
    }

    private int addVersion(int policyId, String user, PolicyConfig config) {
        String json = write(config.validated());
        var keys = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            var statement = connection.prepareStatement(
                "INSERT INTO politica_versoes (fk_id_politica, configuracao, criada_em, criada_por) VALUES (?,?,?,?)",
                java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setInt(1, policyId);
            statement.setString(2, json);
            statement.setTimestamp(3, Timestamp.from(clock.instant()));
            statement.setString(4, user);
            return statement;
        }, keys);
        return keys.getKey().intValue();
    }

    // ---- grupos ----

    public List<Map<String, Object>> groups(int empresa) {
        return jdbc.query("""
            SELECT g.id_grupo, g.nome, g.fk_id_politica, p.nome politica,
              (SELECT COUNT(*) FROM hosts h WHERE h.fk_id_grupo = g.id_grupo AND h.revogado_em IS NULL) hosts
            FROM grupos g LEFT JOIN politicas p ON p.id_politica = g.fk_id_politica
            WHERE g.fk_id_empresa = ? ORDER BY g.nome""", (rs, n) -> {
            var item = new LinkedHashMap<String, Object>();
            item.put("id", rs.getInt("id_grupo"));
            item.put("nome", rs.getString("nome"));
            item.put("politicaId", rs.getObject("fk_id_politica"));
            item.put("politica", rs.getString("politica"));
            item.put("hosts", rs.getInt("hosts"));
            return item;
        }, empresa);
    }

    public Map<String, Object> createGroup(int empresa, String name, Integer policyId) {
        checkPolicy(empresa, policyId);
        var keys = new GeneratedKeyHolder();
        String nome = name(name);
        unique("Já existe um grupo com esse nome.", () -> jdbc.update(connection -> {
            var statement = connection.prepareStatement(
                "INSERT INTO grupos (fk_id_empresa, nome, fk_id_politica) VALUES (?,?,?)", java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setInt(1, empresa);
            statement.setString(2, nome);
            statement.setObject(3, policyId);
            return statement;
        }, keys));
        return Map.of("id", keys.getKey().intValue());
    }

    public void updateGroup(int empresa, int groupId, String name, Integer policyId) {
        checkPolicy(empresa, policyId);
        int changed = unique("Já existe um grupo com esse nome.", () -> jdbc.update(
            "UPDATE grupos SET nome = ?, fk_id_politica = ? WHERE id_grupo = ? AND fk_id_empresa = ?",
            name(name), policyId, groupId, empresa));
        if (changed == 0) throw notFound("Grupo não encontrado.");
    }

    public void deleteGroup(int empresa, int groupId) {
        int changed = jdbc.update("DELETE FROM grupos WHERE id_grupo = ? AND fk_id_empresa = ?", groupId, empresa);
        if (changed == 0) throw notFound("Grupo não encontrado.");
    }

    private void checkPolicy(int empresa, Integer policyId) {
        if (policyId == null) return;
        Integer same = jdbc.queryForObject("SELECT COUNT(*) FROM politicas WHERE id_politica = ? AND fk_id_empresa = ?",
            Integer.class, policyId, empresa);
        if (same == null || same == 0) throw notFound("Política não encontrada.");
    }

    // ---- utilitários ----

    private static int unique(String message, java.util.function.IntSupplier write) {
        try { return write.getAsInt(); }
        catch (org.springframework.dao.DuplicateKeyException e) { throw new ResponseStatusException(HttpStatus.CONFLICT, message); }
    }

    private static String name(String name) {
        String value = name == null ? "" : name.trim();
        if (value.isEmpty() || value.length() > 80 || value.chars().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nome obrigatório (até 80 caracteres).");
        return value;
    }

    private PolicyConfig read(String json) {
        try { return mapper.readValue(json, PolicyConfig.class); }
        catch (JsonProcessingException e) { throw new IllegalStateException("Política gravada inválida.", e); }
    }

    private String write(PolicyConfig config) {
        try { return mapper.writeValueAsString(config); }
        catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    private static ResponseStatusException notFound(String message) {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, message);
    }

    private static ResponseStatusException conflict(String message) {
        return new ResponseStatusException(HttpStatus.CONFLICT, message);
    }
}
