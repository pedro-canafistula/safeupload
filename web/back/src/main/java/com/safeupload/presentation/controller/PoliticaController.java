package com.safeupload.presentation.controller;

import com.safeupload.application.AdminService;
import com.safeupload.application.dto.AdminContracts.DefaultPostResponse;
import com.safeupload.application.dto.AdminContracts.SetPolicyRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/politicas")
public class PoliticaController {
    private final AdminService adminService;

    public PoliticaController(AdminService adminService) {
        this.adminService = adminService;
    }

    @PostMapping
    public ResponseEntity<DefaultPostResponse> publicar(@Valid @RequestBody SetPolicyRequest request) {
        DefaultPostResponse response = adminService.setPolicy(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
