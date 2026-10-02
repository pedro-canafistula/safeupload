package com.safeupload.application.dto;

public class CadastroRequest {

    private String nomeCompleto;
    private String username;
    private String email;
    private String cpf;
    private String senha;
    private String confirmarSenha;
    private String dataNascimento; // formato "yyyy-MM-dd", vem do <input type="date">

    public String getNomeCompleto() { return nomeCompleto; }
    public void setNomeCompleto(String nomeCompleto) { this.nomeCompleto = nomeCompleto; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getCpf() { return cpf; }
    public void setCpf(String cpf) { this.cpf = cpf; }

    public String getSenha() { return senha; }
    public void setSenha(String senha) { this.senha = senha; }

    public String getConfirmarSenha() { return confirmarSenha; }
    public void setConfirmarSenha(String confirmarSenha) { this.confirmarSenha = confirmarSenha; }

    public String getDataNascimento() { return dataNascimento; }
    public void setDataNascimento(String dataNascimento) { this.dataNascimento = dataNascimento; }
}
