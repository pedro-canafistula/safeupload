package com.safeupload.presentation.controller;

import com.safeupload.application.AgentService;
import com.safeupload.application.dto.AgentContracts.*;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/agent")
public class AgentController {
    private final AgentService service;

    public AgentController(AgentService service) { this.service = service; }

    @PostMapping("/heartbeat")
    public HeartbeatResponse heartbeat(@Valid @RequestBody Heartbeat request) { return service.heartbeat(request); }

    @GetMapping("/policy")
    public Policy policy() { return service.policy(); }

    @PostMapping("/events")
    public SubmitResponse events(@Valid @RequestBody SubmitEvents request) { return service.submit(request); }
}
