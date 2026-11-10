package com.safeupload.policy;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.safeupload.presentation.config.CurrentUser;

/** Políticas e grupos da empresa do usuário. SecurityConfig exige ADMIN ou ROOT. */
@RestController
public class PolicyAdminController {
    private static final Logger logger = LoggerFactory.getLogger(PolicyAdminController.class);
    public record PolicyRequest(String nome, Boolean padrao, PolicyConfig configuracao) {}
    public record GroupRequest(String nome, Integer politicaId) {}

    private final PolicyStore policies;
    private final CurrentUser currentUser;

    public PolicyAdminController(PolicyStore policies, CurrentUser currentUser) {
        this.policies = policies;
        this.currentUser = currentUser;
    }

    @GetMapping("/politicas")
    public List<Map<String, Object>> list(Authentication auth) {
        return policies.list(currentUser.of(auth).idEmpresa());
    }

    @GetMapping("/politicas/{id}")
    public Map<String, Object> get(@PathVariable int id, Authentication auth) {
        return policies.get(currentUser.of(auth).idEmpresa(), id);
    }

    @PostMapping("/politicas")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> create(@RequestBody PolicyRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        var result = policies.create(user.idEmpresa(), user.username(), request.nome(), Boolean.TRUE.equals(request.padrao()),
            config(request));
        logger.info("event=admin.policy.created actorId={} companyId={} policyId={} version={}",
            user.idUsuario(), user.idEmpresa(), result.get("id"), result.get("versao"));
        return result;
    }

    @PutMapping("/politicas/{id}")
    public Map<String, Object> update(@PathVariable int id, @RequestBody PolicyRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        var result = policies.update(user.idEmpresa(), id, user.username(), request.nome(),
            Boolean.TRUE.equals(request.padrao()), config(request));
        logger.info("event=admin.policy.updated actorId={} companyId={} policyId={} version={}",
            user.idUsuario(), user.idEmpresa(), id, result.get("versao"));
        return result;
    }

    @DeleteMapping("/politicas/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable int id, Authentication auth) {
        var user = currentUser.of(auth);
        policies.delete(user.idEmpresa(), id);
        logger.info("event=admin.policy.deleted actorId={} companyId={} policyId={}",
            user.idUsuario(), user.idEmpresa(), id);
    }

    @GetMapping("/grupos")
    public List<Map<String, Object>> groups(Authentication auth) {
        return policies.groups(currentUser.of(auth).idEmpresa());
    }

    @PostMapping("/grupos")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> createGroup(@RequestBody GroupRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        var result = policies.createGroup(user.idEmpresa(), request.nome(), request.politicaId());
        logger.info("a event=admin.group.created actorId={} companyId={} groupId={} policyId={}",
            user.idUsuario(), user.idEmpresa(), result.get("id"), request.politicaId());
        return result;
    }

    @PutMapping("/grupos/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateGroup(@PathVariable int id, @RequestBody GroupRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        policies.updateGroup(user.idEmpresa(), id, request.nome(), request.politicaId());
        logger.info("event=admin.group.updated actorId={} companyId={} groupId={} policyId={}",
            user.idUsuario(), user.idEmpresa(), id, request.politicaId());
    }

    @DeleteMapping("/grupos/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteGroup(@PathVariable int id, Authentication auth) {
        var user = currentUser.of(auth);
        policies.deleteGroup(user.idEmpresa(), id);
        logger.info("event=admin.group.deleted actorId={} companyId={} groupId={}",
            user.idUsuario(), user.idEmpresa(), id);
    }

    private static PolicyConfig config(PolicyRequest request) {
        if (request.configuracao() == null)
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.BAD_REQUEST, "Configuração obrigatória.");
        return request.configuracao();
    }
}
