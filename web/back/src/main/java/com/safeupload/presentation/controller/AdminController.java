package com.safeupload.presentation.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.safeupload.application.dto.AdminContracts.DefaultPostResponse;
import com.safeupload.application.dto.AdminContracts.ListPoliciesResponse;
import com.safeupload.application.dto.AdminContracts.SetPolicyRequest;
import com.safeupload.infrastructure.repository.app.PoliticaRepository;

import jakarta.validation.Valid;

@RestController 
@RequestMapping ("/admin")
public class AdminController {
    
    private final PoliticaRepository politicaRepository;

    public AdminController(
        PoliticaRepository politicaRepository
    ){
        this.politicaRepository = politicaRepository;
    }

    @PostMapping ("/policy/set")
    public ResponseEntity<DefaultPostResponse> setPolicy(@Valid @RequestBody SetPolicyRequest request){

    }

    @GetMapping ("/policy/list")
    public ResponseEntity<List<ListPoliciesResponse>> listPolicies(){

    }
}
