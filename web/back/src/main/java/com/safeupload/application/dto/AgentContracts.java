package com.safeupload.application.dto;

import jakarta.validation.constraints.*;


public final class AgentContracts {
    private AgentContracts() {}

    public enum Verdict { Approved, Blocked, AllowedWithoutInspection }
    public enum Category { Cpf, Cnpj, PaymentCard, Password, Secret }

    public record FirstSignalRequest (
        @NotBlank (message="\"hostname\" é obrigatório") 
        @Size(max=100, message="\"hostname\" deve ter no máximo 100 caracteres") 
        String hostname,

        @NotBlank(message="\"ip\" é obrigatório")
         @Size(max=15, message="\"ip\" deve ter no máximo 15 caracteres") 
         String ip,

        @NotBlank (message="\"sistema_operacional\" é obrigatório")
        @Size(max=40, message="\"sistema_operacional\" deve ter no máximo 40 caracteres") 
        String sistema_operacional,

        @NotBlank (message="\"versao_so\" é obrigatório")
        @Size(max=20, message="\"versao_so\" deve ter no máximo 20 caracteres") 
        String versao_so,

        @NotBlank (message="\"fabricante\" é obrigatório")
        @Size(max=50, message="\"fabricante\" deve ter no máximo 50 caracteres") 
        String fabricante,

        @NotBlank (message="\"modelo\" é obrigatório")
        @Size(max=50, message="\"modelo\" deve ter no máximo 50 caracteres") 
        String modelo,

        @NotBlank (message="\"mac_address\" é obrigatório")
        @Size(max=20, message="\"mac_address\" deve ter no máximo 20 caracteres") 
        String mac_address,

        @NotBlank (message="\"numero_serie\" é obrigatório")
        @Size(max=30, message="\"numero_serie\" deve ter no máximo 30 caracteres")
        String numero_serie 
    ){}

    public record FirstSignalResponse (
        int status,
        Integer id_host,
        String descricao
    ) {}

    
}
