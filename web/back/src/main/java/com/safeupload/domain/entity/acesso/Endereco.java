package com.safeupload.domain.entity.acesso;

import jakarta.persistence.*;

@Entity 
@Table (name="enderecos")
public class Endereco {
    @Id 
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name="id_endereco")
    private Integer idEndereco;

    @Column (name="cep")
    private String cep;

    @Column (name="logradouro")
    private String logradouro;

    @Column (name="numero")
    private int numero;

    @Column (name="complemento")
    private String complemento;

    @Column (name="bairro")
    private String bairro;

    @Column (name="cidade")
    private String cidade;

    @Column (name="estado")
    private String estado;

    protected Endereco(){}

    public Endereco(
        String cep,
        String logradouro,
        int numero,
        String complemento,
        String bairro,
        String cidade,
        String estado
    ){
        this.cep = cep;
        this.logradouro = logradouro;
        this.numero = numero;
        this.complemento = complemento;
        this.bairro = bairro;
        this.cidade = cidade;
        this.estado = estado;
    }

    public Integer getIdEndereco(){
        return idEndereco;
    }

    public String getCep(){
        return cep;
    }

    public String getLogradouro(){
        return logradouro;
    }

    public int getNumero(){
        return numero;
    }

    public String getComplemento(){
        return complemento;
    }

    public String getBairro(){
        return bairro;
    }

    public String getCidade(){
        return cidade;
    }

    public String getEstado(){
        return estado;
    }

}
