package com.safeupload.presentation.controller;

import com.safeupload.application.AgentService;
import com.safeupload.application.dto.AgentContracts.*;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import org.springframework.http.HttpStatus;

@RestController
@RequestMapping("/agent/api")
public class AgentController {
    private final AgentService service;

    public AgentController(AgentService service) { this.service = service; }

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

    
}