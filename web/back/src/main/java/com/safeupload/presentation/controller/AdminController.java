package com.safeupload.presentation.controller;

import com.safeupload.application.AdminService;
import com.safeupload.application.dto.AdminViews.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class AdminController {
    private final AdminService service;

    public AdminController(AdminService service) { this.service = service; }

    @GetMapping("/painel")
    public Dashboard dashboard() { return service.dashboard(); }

    @GetMapping("/auditoria")
    public Audit audit(@RequestParam(defaultValue = "") String endpoint) { return service.audit(endpoint); }

    @GetMapping("/endpoints")
    public Endpoints endpoints(@RequestParam(defaultValue = "all") String status,
            @RequestParam(defaultValue = "all") String os, @RequestParam(defaultValue = "") String q) {
        return service.endpoints(status, os, q);
    }
}
