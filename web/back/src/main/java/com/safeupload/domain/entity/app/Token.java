package com.safeupload.domain.entity.app;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity 
@Table (name = "tokens")
public class Token {
    @Id  
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_token")
    private Integer idToken;

    @Column (name = "token")
    private String token;

    @Column (name = "criadoEm")
    private LocalDateTime criadoEm;

    @Column (name = "ativo")
    private Integer ativo;

    protected Token(){}

    public Token(
        String token,
        LocalDateTime criadoEm,
        Integer ativo
    ){
        this.token = token;
        this.criadoEm = criadoEm;
        this.ativo = ativo;
    }

    public String getToken (){
        return token;
    }

    public LocalDateTime getCriadoEm(){
        return criadoEm;
    }

    public Integer getAtivo(){
        return ativo;
    }

    public void desativarToken() {
    this.ativo = 0;
    }
}
