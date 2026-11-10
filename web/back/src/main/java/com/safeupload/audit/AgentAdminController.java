package com.safeupload.audit;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.safeupload.agent.HostStore;
import com.safeupload.presentation.config.CurrentUser;

/** Painel, auditoria, endpoints e tokens de cadastro. SecurityConfig exige ADMIN ou ROOT. */
@RestController
public class AgentAdminController {
    private static final Logger logger = LoggerFactory.getLogger(AgentAdminController.class);
    public record GroupAssignment(Integer grupoId) {}

    private final AgentAdminQueries queries;
    private final HostStore hosts;
    private final CurrentUser currentUser;
    private final com.safeupload.policy.PolicyStore policies;

    public AgentAdminController(AgentAdminQueries queries, HostStore hosts, CurrentUser currentUser,
                                com.safeupload.policy.PolicyStore policies) {
        this.queries = queries;
        this.hosts = hosts;
        this.currentUser = currentUser;
        this.policies = policies;
    }

    @GetMapping("/painel")
    public Map<String, Object> dashboard(Authentication auth) {
        return queries.dashboard(currentUser.of(auth).idEmpresa());
    }

    @GetMapping("/auditoria")
    public Map<String, Object> audit(@RequestParam(required = false) Integer host, Authentication auth) {
        return queries.audit(currentUser.of(auth).idEmpresa(), host);
    }

    @GetMapping("/auditoria/exportar")
    public ResponseEntity<byte[]> export(@RequestParam(required = false) Integer host, Authentication auth) {
        byte[] csv = queries.exportCsv(currentUser.of(auth).idEmpresa(), host).getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
            .contentType(new MediaType("text", "csv", StandardCharsets.UTF_8))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"auditoria-7-dias.csv\"")
            .body(csv);
    }

    @GetMapping("/endpoints")
    public Map<String, Object> endpoints(@RequestParam(defaultValue = "all") String status,
                                         @RequestParam(defaultValue = "") String q, Authentication auth) {
        return queries.endpoints(currentUser.of(auth).idEmpresa(), status, q);
    }

    @PutMapping("/endpoints/{hostId}/grupo")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void assignGroup(@PathVariable int hostId, @RequestBody GroupAssignment request, Authentication auth) {
        var user = currentUser.of(auth);
        policies.assignHostGroup(user.idEmpresa(), hostId, request.grupoId());
        logger.info("event=admin.host.group_assigned actorId={} companyId={} hostId={} groupId={}",
            user.idUsuario(), user.idEmpresa(), hostId, request.grupoId());
    }

    @PostMapping("/endpoints/{hostId}/revogar")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable int hostId, Authentication auth) {
        var user = currentUser.of(auth);
        hosts.revoke(user.idEmpresa(), hostId);
        logger.info("event=admin.host.revoked actorId={} companyId={} hostId={}",
            user.idUsuario(), user.idEmpresa(), hostId);
    }

    @PostMapping("/admin/token")
    public Map<String, Object> issueToken(Authentication auth) {
        var user = currentUser.of(auth);
        var result = hosts.issueToken(user.idEmpresa(), user.username());
        logger.info("event=admin.enrollment_token.issued actorId={} companyId={}",
            user.idUsuario(), user.idEmpresa());
        return result;
    }

    @GetMapping("/admin/tokens")
    public List<Map<String, Object>> tokens(Authentication auth) {
        return hosts.tokens(currentUser.of(auth).idEmpresa());
    }

    @DeleteMapping("/admin/tokens/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteToken(@PathVariable int id, Authentication auth) {
        var user = currentUser.of(auth);
        hosts.deleteToken(user.idEmpresa(), id);
        logger.info("event=admin.enrollment_token.deleted actorId={} companyId={} tokenId={}",
            user.idUsuario(), user.idEmpresa(), id);
    }
}
