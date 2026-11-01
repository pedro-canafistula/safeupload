package com.safeupload.presentation.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.safeupload.application.AdminService;
import com.safeupload.application.dto.AdminContracts.DefaultPostResponse;
import com.safeupload.application.dto.AdminContracts.SetPolicyRequest;

import jakarta.validation.Valid;

@RestController 
@RequestMapping ("/admin")
public class AdminController {
    
    private final AdminService service;

    public AdminController(
        AdminService service
    ){
        this.service = service;
    }

    @PostMapping ("/policy/set")
    public ResponseEntity<DefaultPostResponse> setPolicy(@Valid @RequestBody SetPolicyRequest request){
        DefaultPostResponse response = service.setPolicy(request);
        return ResponseEntity
                .status(HttpStatus.CREATED.value())
                .body(response);
    }

}
