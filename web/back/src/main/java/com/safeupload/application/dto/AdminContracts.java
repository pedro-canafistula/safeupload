package com.safeupload.application.dto;

import org.springframework.http.HttpStatus;

public class AdminContracts {
    private AdminContracts(){}

    public record DefaultPostResponse(
        HttpStatus status,
        String mensagem
    ){}

    public record SetPolicyRequest(){}

    public record ListPoliciesResponse(){}
}
