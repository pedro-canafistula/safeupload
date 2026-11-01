package com.safeupload.domain.entity.app;

import jakarta.persistence.*;

@Entity
@Table(name = "regras")
public class Regras {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_regras")
    private Integer idRegras;

    @Column(name = "bloquear_cpf")
    private Integer bloquearCpf;

    @Column(name = "bloquear_cnpj")
    private Integer bloquearCnpj;

    @Column(name = "bloquear_rg")
    private Integer bloquearRg;

    @Column(name = "bloquear_dados_bancarios")
    private Integer bloquearDadosBancarios;

    @Column(name = "bloquear_cartao_credito")
    private Integer bloquearCartaoCredito;

    @Column(name = "bloquear_credenciais")
    private Integer bloquearCredenciais;

    @Column(name = "bloquear_dados_saude")
    private Integer bloquearDadosSaude;

    @Column(name = "bloquear_dados_pessoais")
    private Integer bloquearDadosPessoais;

    @Column(name = "bloquear_documentos_confidenciais")
    private Integer bloquearDocumentosConfidenciais;

    public Regras() {
    }

    public Regras(
            Integer bloquearCpf,
            Integer bloquearCnpj,
            Integer bloquearRg,
            Integer bloquearDadosBancarios,
            Integer bloquearCartaoCredito,
            Integer bloquearCredenciais,
            Integer bloquearDadosSaude,
            Integer bloquearDadosPessoais,
            Integer bloquearDocumentosConfidenciais) {

        this.bloquearCpf = bloquearCpf;
        this.bloquearCnpj = bloquearCnpj;
        this.bloquearRg = bloquearRg;
        this.bloquearDadosBancarios = bloquearDadosBancarios;
        this.bloquearCartaoCredito = bloquearCartaoCredito;
        this.bloquearCredenciais = bloquearCredenciais;
        this.bloquearDadosSaude = bloquearDadosSaude;
        this.bloquearDadosPessoais = bloquearDadosPessoais;
        this.bloquearDocumentosConfidenciais = bloquearDocumentosConfidenciais;
    }

    public Integer getIdRegras() {
        return idRegras;
    }

    public Integer getBloquearCpf() {
        return bloquearCpf;
    }

    public Integer getBloquearCnpj() {
        return bloquearCnpj;
    }

    public Integer getBloquearRg() {
        return bloquearRg;
    }

    public Integer getBloquearDadosBancarios() {
        return bloquearDadosBancarios;
    }

    public Integer getBloquearCartaoCredito() {
        return bloquearCartaoCredito;
    }

    public Integer getBloquearCredenciais() {
        return bloquearCredenciais;
    }

    public Integer getBloquearDadosSaude() {
        return bloquearDadosSaude;
    }

    public Integer getBloquearDadosPessoais() {
        return bloquearDadosPessoais;
    }

    public Integer getBloquearDocumentosConfidenciais() {
        return bloquearDocumentosConfidenciais;
    }
}