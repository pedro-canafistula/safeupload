package com.safeupload.application.dto;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.http.HttpStatus;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

public class AdminContracts {
    private AdminContracts(){}

    public record DefaultPostResponse(
        HttpStatus status,
        String mensagem
    ){}

    public record SetPolicyRequest(

        @Size(max = 20)
        String versao,

        @Size(max = 50)
        String nome,

        @Valid
        DestinoRequest destino,

        @Size(max = 10)
        String acao,

        List<@Valid RegraRequest> regras,

        OffsetDateTime criadaEm,

        @Size(max = 30)
        String origem

    ) {

        public record DestinoRequest(

            @Size(max = 15)
            String ip

        ) {}

        public record RegraRequest(

            @Size(max = 50)
            String tipo,

            @Size(max = 150)
            String nome

        ) {}
    }
}
