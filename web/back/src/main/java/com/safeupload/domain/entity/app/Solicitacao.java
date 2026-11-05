package com.safeupload.domain.entity.app;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity 
@Table (name="solicitacoes")
public class Solicitacao {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_solicitacao")
    private Integer idSolicitacao;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        name = "fk_id_host",
        nullable = true,
        foreignKey = @ForeignKey (name = "fk_id_host_03")
    )
    private Host host;

    @Column(name = "fk_id_empresa_designada")
    private Integer empresaDesignada;

    @Column(name = "fk_id_admin_designado")
    private Integer adminDesignado;

    @Column(name = "descricao", nullable = false, columnDefinition = "LONGTEXT")
    private String descricao;

    @Column(name = "status")
    private Integer status;

    protected Solicitacao() {
    }

    public Solicitacao(
            Host host,
            Integer empresaDesignada,
            Integer adminDesignado,
            String descricao,
            Integer status) {

        this.host = host;
        this.empresaDesignada = empresaDesignada;
        this.adminDesignado = adminDesignado;
        this.descricao = descricao;
        this.status = status;
    }

    public Integer getIdSolicitacao() {
        return idSolicitacao;
    }

    public Host getHost() {
        return host;
    }

    public Integer getEmpresaDesignada() {
        return empresaDesignada;
    }

    public Integer getAdminDesignado() {
        return adminDesignado;
    }

    public String getDescricao() {
        return descricao;
    }

    public Integer getStatus() {
        return status;
    }
}
