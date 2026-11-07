package com.safeupload.agent;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.safeupload.audit.AgentEventsStore;
import com.safeupload.audit.AuditContracts;
import com.safeupload.policy.PolicyStore;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Rotas do agente (docs/console-agente.md). Todas, menos enroll, chegam aqui já autenticadas pelo AgentAuthFilter. */
@RestController
@RequestMapping("/agent")
public class AgentApiController {
    public record Host(
        @Size(max = 100) String hostname,
        @Size(max = 45) String ip,
        @Min(0) @Max(128) Integer mascara,
        @Size(max = 60) @JsonProperty("sistema_operacional") String sistemaOperacional,
        @Size(max = 40) @JsonProperty("versao_so") String versaoSo,
        @Size(max = 20) @JsonProperty("mac_address") String macAddress) {
        HostStore.HostInfo info() { return new HostStore.HostInfo(hostname, ip, mascara, sistemaOperacional, versaoSo, macAddress); }
    }

    public record EnrollRequest(
        @NotBlank @Size(max = 8) String token,
        @NotBlank @Size(max = 200) @JsonProperty("chave_publica") String chavePublica,
        @NotNull @Valid Host host) {}

    public record HeartbeatRequest(
        @NotNull @Valid Host host,
        @JsonProperty("politica_aplicada") Integer politicaAplicada,
        @Size(max = 50) @JsonProperty("versao_agente") String versaoAgente,
        @Min(0) @Max(100) @JsonProperty("formato_regras") Integer formatoRegras) {}

    private final HostStore hosts;
    private final PolicyStore policies;
    private final AgentEventsStore events;

    public AgentApiController(HostStore hosts, PolicyStore policies, AgentEventsStore events) {
        this.hosts = hosts;
        this.policies = policies;
        this.events = events;
    }

    @PostMapping("/enroll")
    public ResponseEntity<Map<String, Object>> enroll(@Valid @RequestBody EnrollRequest request) {
        try {
            if (!(AgentSignature.publicKey(request.chavePublica()) instanceof java.security.interfaces.EdECPublicKey key)
                    || !key.getParams().getName().equals("Ed25519"))
                throw new IllegalArgumentException();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Chave pública Ed25519 inválida.");
        }
        int id = hosts.enroll(request.token(), request.chavePublica(), request.host().info());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id_host", id));
    }

    @PostMapping("/heartbeat")
    public Map<String, Object> heartbeat(@RequestAttribute(AgentAuthFilter.HOST_ID) int hostId,
                                         @Valid @RequestBody HeartbeatRequest request) {
        hosts.heartbeat(hostId, request.host().info(), request.politicaAplicada(), request.versaoAgente(),
            request.formatoRegras() == null ? 0 : request.formatoRegras());
        return Map.of("id_host", hostId);
    }

    @GetMapping("/policy")
    public ResponseEntity<Map<String, Object>> policy(@RequestAttribute(AgentAuthFilter.HOST_ID) int hostId) {
        return policies.agentDocumentForHost(hostId)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/events")
    public AuditContracts.Receipt events(@RequestAttribute(AgentAuthFilter.HOST_ID) int hostId,
                                         @Valid @RequestBody AuditContracts.Batch batch) {
        return events.accept(batch, hostId);
    }
}
