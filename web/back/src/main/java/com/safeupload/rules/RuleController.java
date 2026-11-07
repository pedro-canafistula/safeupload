package com.safeupload.rules;

import java.util.List;
import java.util.Map;

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

import com.safeupload.policy.PolicyStore;
import com.safeupload.presentation.config.CurrentUser;

/** Regras personalizadas da empresa (docs/console-agente.md). SecurityConfig exige ADMIN ou ROOT. */
@RestController
public class RuleController {
    public record RuleRequest(String nome, String descricao, RuleDefinition.Condition quando, RuleDefinition.Examples exemplos) {}
    public record TestRequest(RuleDefinition.Condition quando, List<String> textos) {}

    private final RuleStore rules;
    private final PolicyStore policies;
    private final CurrentUser currentUser;

    public RuleController(RuleStore rules, PolicyStore policies, CurrentUser currentUser) {
        this.rules = rules;
        this.policies = policies;
        this.currentUser = currentUser;
    }

    @GetMapping("/regras")
    public List<Map<String, Object>> list(Authentication auth) {
        return rules.list(currentUser.of(auth).idEmpresa());
    }

    @GetMapping("/regras/{id}")
    public Map<String, Object> get(@PathVariable int id, Authentication auth) {
        return rules.get(currentUser.of(auth).idEmpresa(), id);
    }

    @PostMapping("/regras")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> create(@RequestBody RuleRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        return rules.create(user.idEmpresa(), user.username(), request.nome(), request.descricao(),
            new RuleDefinition(request.quando(), request.exemplos()));
    }

    @PutMapping("/regras/{id}")
    public Map<String, Object> update(@PathVariable int id, @RequestBody RuleRequest request, Authentication auth) {
        var user = currentUser.of(auth);
        return rules.update(user.idEmpresa(), id, user.username(), request.nome(), request.descricao(),
            new RuleDefinition(request.quando(), request.exemplos()), (empresa, ruleId, author) -> {
                policies.bumpForRule(empresa, ruleId, author);
                policies.requireRuleSupport(empresa);
            });
    }

    @DeleteMapping("/regras/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable int id, Authentication auth) {
        rules.delete(currentUser.of(auth).idEmpresa(), id);
    }

    /** Avalia condições (ainda não salvas) sobre textos de exemplo, como o agente avaliaria. */
    @PostMapping("/regras/testar")
    public List<RuleDefinition.Evaluation> test(@RequestBody TestRequest request, Authentication auth) {
        currentUser.of(auth);
        return rules.test(request.quando(), request.textos());
    }
}
