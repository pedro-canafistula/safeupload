package com.safeupload.application.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import org.springframework.http.HttpStatus;
import java.time.LocalDateTime;
import java.util.List;


public final class AgentContracts {
    private AgentContracts() {}

    public record DefaultResponse (
        HttpStatus status,
        String mensagem
    ){}

    public record BasicAuthRequest(
        @NotNull (message = "\"id_host\" é obrigatório")
        Integer id_host,

        @NotBlank (message = "\"assinatura\" é obrigatório")
        String assinatura
    ){}
    

    public record PolicyRequest(
        Integer id_host
    ){}

    public record PolicyResponse(
        Integer idPolitica,
        String versao,
        String nome,
        PolicyDestination destino,
        String acao,
        List<PolicyRule> regras,
        LocalDateTime criadaEm,
        String origem
    ) {}

    public record PolicyDestination(Integer idHost, String ip) {}

    public record PolicyRule(String tipo, String nome) {}

    public record HostRequest(
        @Size(max=15, message="\"ip\" deve ter no máximo 15 caracteres")
        String ip,

        @Min(value=0, message="\"mascara\" deve estar entre 0 e 32")
        @Max(value=32, message="\"mascara\" deve estar entre 0 e 32")
        Integer mascara,

        @Size(max=100, message="\"hostname\" deve ter no máximo 100 caracteres")
        String hostname,

        @Size(max=40, message="\"sistema_operacional\" deve ter no máximo 40 caracteres")
        String sistema_operacional,

        @Size(max=20, message="\"versao_so\" deve ter no máximo 20 caracteres")
        String versao_so,

        @Size(max=20, message="\"mac_address\" deve ter no máximo 20 caracteres") 
        String mac_address
    ) {}

    public record FirstContactRequest(
        @NotNull (message = "\"token\" é obrigatório")
        String token,

        @NotNull (message = "\"chave_publica\" é obrigatório")
        String chave_publica
    ){}


    public record HeartBeatRequest (
        @Valid 
        FirstContactRequest cadastro,

        @Valid
        BasicAuthRequest autenticacao,

        @NotNull (message = "\"host\" é obrigatório")
        @Valid 
        HostRequest host
    ){
        public HeartBeatRequest {
            if (cadastro == null && autenticacao == null) {
                throw new IllegalArgumentException(
                    "É necessário informar \"cadastro\" ou \"autenticacao\"."
                );
            }

            if ((cadastro != null) == (autenticacao != null)) {
                throw new IllegalArgumentException(
                    "Informe \"cadastro\" ou \"autenticacao\", mas não ambos."
                );
            }
        }
    }

    public record RegrasResponse(
            Integer bloquear_cpf,
            Integer bloquear_cnpj,
            Integer bloquear_rg,
            Integer bloquear_dados_bancarios,
            Integer bloquear_cartao_credito,
            Integer bloquear_credenciais,
            Integer bloquear_dados_saude,
            Integer bloquear_dados_pessoais,
            Integer bloquear_documentos_confidenciais
    ){}

    public record PoliticaResponse (
        Integer id_politica,
        String versao,
        String nome,
        String acao,
        String origem,
        RegrasResponse regras
    ){   
    }

    public record HeartBeatResponse (
        DefaultResponse resposta,
        int id_host,
        PoliticaResponse politica
    ){}

    public record TicketsRequest(
        Integer fk_id_host,
        Integer fk_id_empresa_designada,
        Integer fk_id_admin_designado,
        String descricao
    ){}

    public record ListEmpresaResponse(
        Integer id_empresa,
        String razao_social
    ){}

}
