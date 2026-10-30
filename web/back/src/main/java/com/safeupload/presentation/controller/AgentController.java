package com.safeupload.presentation.controller;

import com.safeupload.application.AgentService;
import com.safeupload.application.AdminService;
import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.application.dto.AuthContracts.ListEmpresaResponse;
//import com.safeupload.domain.entity.app.Politica;
import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;
//import com.safeupload.infrastructure.repository.app.PoliticaRepository;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/agent")
public class AgentController {
    private final AgentService service;
    private final AdminService adminService;
    private final EmpresaRepository empresaRepository;
    //private final PoliticaRepository politicaRepository;

    public AgentController(
        AgentService service,
        AdminService adminService,
        EmpresaRepository empresaRepository
        //PoliticaRepository politicaRepository
    ) {
        this.service = service; 
        this.adminService = adminService;
        this.empresaRepository = empresaRepository;
        //this.politicaRepository = politicaRepository;
    }

    @PostMapping("/synchronize")
    public ResponseEntity <SynchronizeResponse> synchronize(@Valid @RequestBody SynchronizeRequest request) {
        SynchronizeResponse response = service.synchronize(request);
        return ResponseEntity
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

    @PostMapping ("/heartbeat")
    public ResponseEntity <DefaultResponse> heartbeat(@Valid @RequestBody HeartbeatRequest request){
        DefaultResponse response = service.heartbeat(request);
        return ResponseEntity
                .status(HttpStatus.OK.value())
                .body(response);
    }

    @GetMapping("/empresa/list")
    public ResponseEntity<List<ListEmpresaResponse>> listEmpresa(){
        List<ListEmpresaResponse> response = empresaRepository.findAll()
                .stream()
                .map(empresa -> new ListEmpresaResponse(
                    empresa.getIdEmpresa(),
                    empresa.getRazaoSocial()
                ))
                .toList();
        return ResponseEntity.ok(response);
    }

    @PostMapping ("/tickets")
    public ResponseEntity <DefaultResponse> tickets (@Valid @RequestBody TicketsRequest request){
        DefaultResponse response = service.tickets(request);
        return ResponseEntity
                .status(HttpStatus.OK.value())
                .body(response);
    }

    @GetMapping("/api/policy")
    public ResponseEntity<PolicyResponse> policy(@RequestParam("ip") String ip) {
        return adminService.latestPolicyForIp(ip)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // @GetMapping ("/policies")
    // public ResponseEntity <PolicyResponse> policy (@Valid @RequestBody PolicyRequest request){
    //     List <Politica> politica = politicaRepository.findByFkIdHost_IdHost(request.id_host());
    //     return ResponseEntity.ok(response);
    // }
}
