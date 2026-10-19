package com.safeupload.domain.entity.app;

import java.time.LocalDateTime;

import jakarta.persistence.*;

@Entity 
@Table (name ="politicas")
public class Politica {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_politica")
    private Integer idPolitica;

    @Column(name = "versao", length = 20)
    private String versao;

    @Column(name = "nome", length = 50)
    private String nome;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        name = "fk_id_host",
        nullable = false,
        foreignKey = @ForeignKey(name = "fk_id_host_02")
    )
    private Host fkIdHost;

    @Column(name = "acao", length = 10)
    private String acao;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        name = "fk_id_regras",
        foreignKey = @ForeignKey(name = "fk_id_regras")
    )
    private Regras fkIdRegras;

    @Column(name = "criadaEm")
    private LocalDateTime criadaEm;

    @Column(name = "origem", length = 30)
    private String origem;

    protected  Politica() {
    }

    public Politica(
            String versao,
            String nome,
            Host fkIdHost,
            String acao,
            Regras fkIdRegras,
            LocalDateTime criadaEm,
            String origem) {

        this.versao = versao;
        this.nome = nome;
        this.fkIdHost = fkIdHost;
        this.acao = acao;
        this.fkIdRegras = fkIdRegras;
        this.criadaEm = criadaEm;
        this.origem = origem;
    }

    public Integer getIdPolitica() {
        return idPolitica;
    }

    public String getVersao() {
        return versao;
    }

    public String getNome() {
        return nome;
    }

    public Host getFkIdHost() {
        return fkIdHost;
    }

    public String getAcao() {
        return acao;
    }

    public Regras getFkIdRegras() {
        return fkIdRegras;
    }

    public LocalDateTime getCriadaEm() {
        return criadaEm;
    }

    public String getOrigem() {
        return origem;
    }
}
