package com.safeupload.presentation.controller;

import com.safeupload.application.AgentService;
import com.safeupload.application.dto.AgentContracts.*;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/agent/api")
public class AgentController {
    private final AgentService service;

    public AgentController(AgentService service) { this.service = service; }

    @PostMapping("/firstsignal")
    public ResponseEntity <FirstSignalResponse> firstsignal(@Valid @RequestBody FirstSignalRequest request) {
        FirstSignalResponse response = service.firstSignal(request);
        return ResponseEntity
                .status(response.status())
                .body(response);
    }

}