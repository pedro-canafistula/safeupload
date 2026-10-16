package com.safeupload.application;

import org.springframework.stereotype.Service;

import com.safeupload.application.dto.AdminContracts.DefaultPostResponse;
import com.safeupload.application.dto.AdminContracts.SetPolicyRequest;
import com.safeupload.infrastructure.repository.app.PoliticaRepository;

@Service 
public class AdminService {
    private final PoliticaRepository politicaRepository;

    public AdminService (
        PoliticaRepository politicaRepository
    ){
        this.politicaRepository = politicaRepository;
    }

    public DefaultPostResponse setPolicy(SetPolicyRequest request){

    }

}
