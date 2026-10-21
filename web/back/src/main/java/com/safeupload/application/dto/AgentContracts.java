package com.safeupload.application.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import org.springframework.http.HttpStatus;


public final class AgentContracts {
    private AgentContracts() {}

    public record HostRequest(
         @Size(max=15, message="\"ip\" deve ter no máximo 15 caracteres")
        String ip,

        @Min(value=0, message="\"mascara\" deve estar entre 0 e 32")
        @Max(value=32, message="\"mascara\" deve estar entre 0 e 32")
        int mascara,

        @Size(max=100, message="\"hostname\" deve ter no máximo 100 caracteres")
        String hostname,

        @Size(max=40, message="\"sistema_operacional\" deve ter no máximo 40 caracteres")
        String sistema_operacional,

        @Size(max=20, message="\"versao_so\" deve ter no máximo 20 caracteres")
        String versao_so,

        @Size(max=50, message="\"fabricante\" deve ter no máximo 50 caracteres") 
        String fabricante,

        @Size(max=50, message="\"modelo\" deve ter no máximo 50 caracteres") 
        String modelo,

        @Size(max=20, message="\"mac_address\" deve ter no máximo 20 caracteres") 
        String mac_address,

        @Size(max=30, message="\"numero_serie\" deve ter no máximo 30 caracteres")
        String numero_serie
    ) {}

    public record UsuarioSoRequest(
        @Size (max=50, message = "\"sid\" deve ter no máximo 50 caracteres")
        String sid,

        @Size (max=40, message = "\"usuario_so\" deve ter no máximo 40 caracteres")
        String usuario_so,

        @Size (max=50, message = "\"dominio\" deve ter no máximo 50 caracteres")
        String dominio,

        @Min(value=0, message = "O valor de \"admin\" deve ser 0 ou 1")
        @Max(value=1, message = "O valor de \"admin\" deve ser 0 ou 1")
        int admin
    ) {}

    public record SynchronizeRequest (
        @NotNull
        @Valid
        HostRequest host,

        @NotNull
        @Valid 
        UsuarioSoRequest usuarioSo
    ){}

    public record SynchronizeResponse (
        HttpStatus status,
        Integer id_host,
        Integer id_usuario_so
    ){}

    public record HeartbeatRequest (
        @NotNull (message = "\"id_usuario_so\" não pode estar vazio")
        Integer id_usuario_so
    ){}

    public record HeartbeatResponse (
        HttpStatus status,
        String mensagem
    ){}

    public record TicketsRequest(
        Integer fk_id_usuario_so,
        Integer fk_id_empresa_designada,
        Integer fk_id_admin_designado,
        String descricao
    ){}

    public record TicketsResponse (
        HttpStatus status,
        String mensagem
    ){}

    public record ListEmpresaResponse(
        Integer id_empresa,
        String razao_social
    ){}
    
}
