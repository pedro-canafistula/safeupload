package com.safeupload.agent;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Máquinas cadastradas e tokens de cadastro (schema app). */
@Service
public class HostStore {
    public static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final String TOKEN_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    public record Credentials(String publicKey, boolean revoked) {}
    public record HostInfo(String hostname, String ip, Integer mascara, String sistemaOperacional,
                           String versaoSo, String macAddress) {}

    private final JdbcTemplate jdbc;
    private final Clock clock;

    public HostStore(@Qualifier("appJdbc") JdbcTemplate jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    private Timestamp now() { return Timestamp.from(clock.instant()); }

    public Credentials credentials(int hostId) {
        var rows = jdbc.query("SELECT chave_publica, revogado_em FROM hosts WHERE id_host=?",
            (rs, n) -> new Credentials(rs.getString(1), rs.getTimestamp(2) != null), hostId);
        return rows.isEmpty() ? null : rows.getFirst();
    }

    public int empresaOf(int hostId) {
        return jdbc.queryForObject("SELECT fk_id_empresa FROM hosts WHERE id_host=?", Integer.class, hostId);
    }

    /** Consome o token e cria o host. A recuperação autenticada apenas devolve o cadastro anterior. */
    @Transactional("appTransactionManager")
    public int enroll(String token, String publicKey, HostInfo host, boolean recovery) {
        var rows = jdbc.queryForList(
            "SELECT id_token, fk_id_empresa, criado_em, usado_em, fk_id_host FROM tokens WHERE token=? FOR UPDATE", token);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token inválido.");
        var row = rows.getFirst();
        Instant created = ((Timestamp) row.get("criado_em")).toInstant();
        if (created.plus(TOKEN_LIFETIME).isBefore(clock.instant()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token usado ou expirado.");
        if (row.get("usado_em") != null) {
            if (!recovery || !(row.get("fk_id_host") instanceof Number registered))
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token usado ou expirado.");
            int hostId = registered.intValue();
            var matched = jdbc.query("SELECT chave_publica, revogado_em FROM hosts WHERE id_host=? AND fk_id_empresa=? FOR SHARE",
                (rs, n) -> new Credentials(rs.getString(1), rs.getTimestamp(2) != null), hostId, row.get("fk_id_empresa"));
            if (matched.isEmpty() || !publicKey.equals(matched.getFirst().publicKey()))
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token usado ou expirado.");
            if (matched.getFirst().revoked())
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Máquina revogada no console.");
            return hostId;
        }
        var keys = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            var statement = connection.prepareStatement("""
                INSERT INTO hosts (fk_id_empresa, chave_publica, hostname, ip, mascara, sistema_operacional, versao_so,
                    mac_address, cadastrado_em, visto_por_ultimo) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setInt(1, ((Number) row.get("fk_id_empresa")).intValue());
            statement.setString(2, publicKey);
            statement.setString(3, host.hostname());
            statement.setString(4, host.ip());
            statement.setObject(5, host.mascara());
            statement.setString(6, host.sistemaOperacional());
            statement.setString(7, host.versaoSo());
            statement.setString(8, host.macAddress());
            statement.setTimestamp(9, now());
            statement.setTimestamp(10, now());
            return statement;
        }, keys);
        int hostId = keys.getKey().intValue();
        jdbc.update("UPDATE tokens SET usado_em=?, fk_id_host=? WHERE id_token=?", now(), hostId, row.get("id_token"));
        return hostId;
    }

    public void heartbeat(int hostId, HostInfo host, Integer appliedPolicy, String agentVersion, int rulesFormat) {
        jdbc.update("""
            UPDATE hosts SET hostname=?, ip=?, mascara=?, sistema_operacional=?, versao_so=?, mac_address=?,
                versao_agente=?, formato_regras=?, politica_aplicada=?, visto_por_ultimo=? WHERE id_host=?""",
            host.hostname(), host.ip(), host.mascara(), host.sistemaOperacional(), host.versaoSo(),
            host.macAddress(), agentVersion, rulesFormat, appliedPolicy, now(), hostId);
    }

    // ---- administração (sempre dentro da empresa) ----

    public Map<String, Object> issueToken(int empresa, String createdBy) {
        for (int attempt = 0; attempt < 5; attempt++) {
            var token = new StringBuilder(8);
            for (int i = 0; i < 8; i++) token.append(TOKEN_CHARS.charAt(RANDOM.nextInt(TOKEN_CHARS.length())));
            Integer exists = jdbc.queryForObject("SELECT COUNT(*) FROM tokens WHERE token=?", Integer.class, token.toString());
            if (exists != null && exists > 0) continue;
            Timestamp created = now();
            jdbc.update("INSERT INTO tokens (fk_id_empresa, token, criado_em, criado_por) VALUES (?,?,?,?)",
                empresa, token.toString(), created, createdBy);
            return Map.of("token", token.toString(), "expiraEm", created.toInstant().plus(TOKEN_LIFETIME).toString());
        }
        throw new IllegalStateException("Não foi possível gerar um token único.");
    }

    public List<Map<String, Object>> tokens(int empresa) {
        Instant now = clock.instant();
        return jdbc.query("""
            SELECT id_token, token, criado_em, criado_por, usado_em, fk_id_host FROM tokens
            WHERE fk_id_empresa=? ORDER BY id_token DESC LIMIT 200""", (rs, n) -> {
            Instant created = rs.getTimestamp("criado_em").toInstant();
            Timestamp used = rs.getTimestamp("usado_em");
            boolean expired = created.plus(TOKEN_LIFETIME).isBefore(now);
            String state = used != null ? "usado" : expired ? "expirado" : "ativo";
            var item = new LinkedHashMap<String, Object>();
            item.put("id", rs.getInt("id_token"));
            item.put("token", state.equals("ativo") ? rs.getString("token") : null);
            item.put("estado", state);
            item.put("criadoEm", created.toString());
            item.put("expiraEm", created.plus(TOKEN_LIFETIME).toString());
            item.put("criadoPor", rs.getString("criado_por"));
            item.put("usadoEm", used == null ? null : used.toInstant().toString());
            item.put("hostId", rs.getObject("fk_id_host"));
            return item;
        }, empresa);
    }

    public void deleteToken(int empresa, int tokenId) {
        int changed = jdbc.update("DELETE FROM tokens WHERE id_token=? AND fk_id_empresa=? AND usado_em IS NULL",
            tokenId, empresa);
        if (changed == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Token não encontrado ou já usado.");
    }

    public void revoke(int empresa, int hostId) {
        int changed = jdbc.update("UPDATE hosts SET revogado_em=COALESCE(revogado_em, ?) WHERE id_host=? AND fk_id_empresa=?",
            now(), hostId, empresa);
        if (changed == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Máquina não encontrada.");
    }
}
