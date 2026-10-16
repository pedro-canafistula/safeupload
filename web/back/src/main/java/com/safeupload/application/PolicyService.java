package com.safeupload.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.application.dto.PolicyPublication.*;
import com.safeupload.domain.entity.Endpoint;
import com.safeupload.domain.entity.PublishedPolicy;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.time.Clock;
import java.util.*;

@Service
public class PolicyService {
    private final EntityManager entities;
    private final ObjectMapper mapper;
    private final Clock clock;
    public PolicyService(EntityManager entities, ObjectMapper mapper, Clock clock) {
        this.entities = entities; this.mapper = mapper; this.clock = clock;
    }

    public static Policy defaultPolicy() {
        return new Policy(1, List.of(Category.values()),
                new MonitoredScopes(List.of(".txt", ".csv", ".docx", ".xlsx", ".pdf"),
                        List.of("C:\\SafeUpload\\Escopo Monitorado"), List.of(), true, true),
                20, 5, false, false, true, List.of("System", "SafeUpload.Agent.App"),
                new Clipboard(ClipboardMode.Off,
                        List.of("chrome", "msedge", "firefox", "brave", "opera", "WhatsApp", "Telegram", "ms-teams", "slack", "Discord", "OUTLOOK", "thunderbird"),
                        List.of("KeePass", "KeePassXC", "1Password", "Bitwarden"), 100_000, true));
    }

    @Transactional(readOnly = true)
    public Policy policy(String endpointId) {
        if (endpointId == null || endpointId.isBlank()) return defaultPolicy();
        var saved = entities.find(PublishedPolicy.class, endpointId);
        return saved == null ? defaultPolicy() : decode(saved);
    }

    @Transactional(readOnly = true)
    public List<Published> publications() {
        return entities.createQuery("select p from PublishedPolicy p order by p.publishedAt desc", PublishedPolicy.class)
                .getResultList().stream().map(p -> new Published(p.getEndpointId(), p.getName(),
                        p.getPolicyVersion(), p.getPublishedAt(), decode(p))).toList();
    }

    @Transactional
    public Published publish(Request request) {
        if (!"bloquear".equals(request.acao())) throw badRequest("Modo de alerta ainda não disponível no publicador.");
        var categories = new LinkedHashSet<Category>();
        var types = new HashSet<String>();
        for (var rule : request.regras()) {
            if (!types.add(rule.tipo())) throw badRequest("Regra repetida: " + rule.tipo());
            switch (rule.tipo()) {
                case "cpf" -> categories.add(Category.Cpf);
                case "cnpj" -> categories.add(Category.Cnpj);
                case "cartao_credito" -> categories.add(Category.PaymentCard);
                case "credenciais" -> { categories.add(Category.Password); categories.add(Category.Secret); }
                default -> throw badRequest("Regra ainda não suportada pelo agente: " + rule.tipo());
            }
        }
        var endpointId = request.destino().endpointId();
        // Lock the existing inventory row, including the first publication, until commit.
        if (entities.find(Endpoint.class, endpointId, LockModeType.PESSIMISTIC_WRITE) == null)
            throw badRequest("Computador não registrado. Aguarde o heartbeat do agente.");
        var previous = entities.find(PublishedPolicy.class, endpointId);
        int version = previous == null ? 2 : Math.addExact(previous.getPolicyVersion(), 1);
        var base = defaultPolicy();
        var policy = new Policy(version, List.copyOf(categories), base.monitoredScopes(), base.maxFileSizeMb(),
                base.inspectionTimeoutSeconds(), false, base.overrideAllowed(),
                base.failOpen(), base.excludedProcesses(), base.clipboard());
        var now = clock.instant();
        try {
            entities.merge(new PublishedPolicy(endpointId, request.nome().trim(), version, now,
                    mapper.writeValueAsString(policy)));
        } catch (JsonProcessingException e) { throw new IllegalStateException("Falha ao serializar política.", e); }
        return new Published(endpointId, request.nome().trim(), version, now, policy);
    }

    private Policy decode(PublishedPolicy saved) {
        try { return mapper.readValue(saved.getDocument(), Policy.class); }
        catch (JsonProcessingException e) { throw new IllegalStateException("Política persistida inválida.", e); }
    }
    private ResponseStatusException badRequest(String reason) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, reason);
    }
}
