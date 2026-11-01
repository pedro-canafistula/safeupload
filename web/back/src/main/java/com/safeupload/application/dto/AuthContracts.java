package com.safeupload.application.dto;

import org.springframework.http.HttpStatus;

import jakarta.validation.Valid;

import java.time.LocalDate;

import jakarta.validation.constraints.*;

public class AuthContracts {
    private AuthContracts(){}

    public record DefaultPostResponse(
        HttpStatus status,
        String mensagem
    ){}

    public record DecisionResponse(
        HttpStatus status,
        boolean existemUsuarios
    ){}

    public record UsuarioSessaoResponse(
        Integer idUsuario,
        String nomeCompleto,
        String username,
        String email,
        String role
    ){}

    public record EnderecoRegister(
        @NotBlank 
        @Size(min=9, max=9)
        String cep,

        @NotBlank 
        @Size(max=40)
        String logradouro,

        @Min(0)
        int numero,

        @Size(max=100)
        String complemento,

        @NotBlank 
        @Size(max=30)
        String bairro,

        @NotBlank 
        @Size(max=40)
        String cidade,

        @NotBlank 
        @Size(max=2)
        String estado
    ){}

    public record EmpresaRegister (
        @NotBlank 
        @Size(max=100)
        String razao_social,

        @NotBlank 
        @Size(max=100)
        String nome_fantasia,

        @NotBlank 
        @Size(min=14, max=14)
        String cnpj,

        @NotBlank 
        @Size(max=100)
        String email_contato,

        @NotBlank 
        @Size (max=14)
        String telefone_contato,

        @Valid
        EnderecoRegister endereco
    ){}


    public record FirstRegisterRequest(
        @NotBlank 
        @Size(max=50)
        String username,

        @NotBlank 
        @Size(max=75)
        String email,

        @NotBlank 
        @Size(max=14)
        String cpf,

        @NotBlank 
        @Size(max=60)
        String senha,

        @NotBlank 
        @Size(max=100)
        String nome_completo,

        @NotNull 
        LocalDate data_nascimento,

        @Valid 
        EmpresaRegister empresa,

        @Valid 
        EnderecoRegister endereco
    ){}


    public record ListEmpresaResponse(
        Integer id_empresa,
        String razao_social
    ){}

    public record UsuarioRegister(
        @NotBlank 
        @Size(max=50)
        String username,

        @NotBlank 
        @Size(max=75)
        String email,

        @NotBlank 
        @Size(max=14)
        String cpf,

        @NotBlank 
        @Size(max=60)
        String senha,

        @NotBlank 
        @Size(max=100)
        String nome_completo,

        @NotNull 
        LocalDate data_nascimento,

        @NotNull 
        Integer fk_id_empresa,

        @Valid 
        EnderecoRegister endereco,

        @NotBlank 
        @Size(max=20)
        String role,

        @NotBlank 
        @Size(max=50)
        String criado_por
    ){}

    public record LoginRequest(
        @NotBlank 
        @Size (max=75)
        String email,

        @NotBlank 
        @Size (max=30)
        String senha
    ){}

}
