package com.safeupload.presentation.controller;

import com.safeupload.application.AgentService;
import com.safeupload.application.dto.AgentContracts.*;
import com.safeupload.application.dto.AuthContracts.ListEmpresaResponse;
import com.safeupload.infrastructure.repository.acesso.EmpresaRepository;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.util.List;

import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/agent/api")
public class AgentController {
    private final AgentService service;
    private final EmpresaRepository empresaRepository;

    public AgentController(
        AgentService service,
        EmpresaRepository empresaRepository
    ) {
        this.service = service; 
        this.empresaRepository = empresaRepository;
    }

    @PostMapping("/synchronize")
    public ResponseEntity <SynchronizeResponse> synchronize(@Valid @RequestBody SynchronizeRequest request) {
        SynchronizeResponse response = service.synchronize(request);
        return ResponseEntity
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

    @PostMapping ("/heartbeat")
    public ResponseEntity <HeartbeatResponse> heartbeat(@Valid @RequestBody HeartbeatRequest request){
        HeartbeatResponse response = service.heartbeat(request);
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
    public ResponseEntity <TicketsResponse> tickets (@Valid @RequestBody TicketsRequest request){
        TicketsResponse response = service.tickets(request);
        return ResponseEntity
                .status(HttpStatus.OK.value())
                .body(response);
    }

    
}