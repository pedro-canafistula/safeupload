package com.safeupload.application.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

import com.safeupload.domain.entity.app.Host;
import com.safeupload.domain.entity.app.UsuarioSo;

import io.micrometer.common.lang.NonNull;

public final class AgentContracts {
    private AgentContracts() {}

    public record HostRequest(
        @NotBlank (message = "\"hostname\" não pode estar vazio")
        @Size(max=100, message="\"hostname\" deve ter no máximo 100 caracteres")
        String hostname,

        @NotBlank (message = "\"ip\" não pode estar vazio")
        @Size(max=15, message="\"ip\" deve ter no máximo 15 caracteres")
        String ip,

        @NotBlank (message = "\"sistema_operacional\" não pode estar vazio")
        @Size(max=40, message="\"sistema_operacional\" deve ter no máximo 40 caracteres")
        String sistema_operacional,

        @NotBlank (message = "\"versao_so\" não pode estar vazio")
        @Size(max=20, message="\"versao_so\" deve ter no máximo 20 caracteres")
        String versao_so,

        @NotBlank (message = "\"fabricante\" não pode estar vazio")
        @Size(max=50, message="\"fabricante\" deve ter no máximo 50 caracteres") 
        String fabricante,

        @NotBlank (message = "\"modelo\" não pode estar vazio")
        @Size(max=50, message="\"modelo\" deve ter no máximo 50 caracteres") 
        String modelo,

        @NotBlank (message = "\"mac_address\" não pode estar vazio")
        @Size(max=20, message="\"mac_address\" deve ter no máximo 20 caracteres") 
        String mac_address,

        @NotBlank (message = "\"numero_serie\" não pode estar vazio")
        @Size(max=30, message="\"numero_serie\" deve ter no máximo 30 caracteres")
        String numero_serie
    ) {}

    public record UsuarioSoRequest(
        @NotBlank (message = "\"sid\" não pode estar vazio")
        @Size (max=50, message = "\"sid\" deve ter no máximo 50 caracteres")
        String sid,

        @NotBlank (message = "\"usuario_so\" não pode estar vazio")
        @Size (max=40, message = "\"usuario_so\" deve ter no máximo 40 caracteres")
        String usuario_so,

        @NotBlank (message = "\"dominio\" não pode estar vazio")
        @Size (max=50, message = "\"dominio\" deve ter no máximo 50 caracteres")
        String dominio,

        @NotNull (message = "\"admin\" não pode estar vazio")
        @Min(value=0, message = "O valor de \"admin\" deve ser 0 ou 1")
        @Max(value=1, message = "O valor de \"admin\" deve ser 0 ou 1")
        int admin
    ) {}

    public record FirstSignalRequest (
        @NotNull
        @Valid
        HostRequest host,

        @NotNull
        @Valid 
        UsuarioSoRequest usuarioSo
    ){}

    public record FirstSignalResponse (
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
}
