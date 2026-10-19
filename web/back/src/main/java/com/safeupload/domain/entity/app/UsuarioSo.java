package com.safeupload.domain.entity.app;

import java.time.LocalDateTime;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import jakarta.persistence.*;

@Entity 
@Table (name="usuarios_so")
public class UsuarioSo {
    @Id 
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name="id_usuario_so")
    private Integer idUsuarioSo;

    @Column (name="sid")
    private String sid;

    @Column(name="usuario_so")
    private String usuarioSo;

    @Column(name="dominio")
    private String dominio;

    @Column(name="admin")
    private int admin;

    @Column(name = "visto_por_ultimo", columnDefinition = "TIMESTAMP")
    private LocalDateTime vistoPorUltimo;

    @Column(name="ativo")
    private int ativo;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
        name="fk_id_host",
        nullable=false,
        foreignKey = @ForeignKey (name = "fk_id_host_01")
    )
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Host fkIdHost;

    protected UsuarioSo(){}

    public UsuarioSo(
        String sid,
        String usuarioSo,
        String dominio,
        int admin,
        LocalDateTime vistoPorUltimo,
        int ativo,
        Host fkIdHost
    ){
        this.sid = sid;
        this.usuarioSo = usuarioSo;
        this.dominio = dominio;
        this.admin = admin;
        this.vistoPorUltimo = vistoPorUltimo;
        this.ativo = ativo;
        this.fkIdHost = fkIdHost;
    }

    public Integer getIdUsuarioSo(){
        return idUsuarioSo;
    }

    public String getSid(){
        return sid;
    }

    public String getUsuarioSo(){
        return usuarioSo;
    }

    public String getDominio(){
        return dominio;
    }

    public int getAdmin(){
        return admin;
    }

    public LocalDateTime getVistoPorUltimo(){
        return vistoPorUltimo;
    }

    public int getAtivo(){
        return ativo;
    }

    public Host getFkIdHost(){
        return fkIdHost;
    }

    public void executeHeartbeat(LocalDateTime vistoPorUltimo, int ativo) {
        this.vistoPorUltimo = vistoPorUltimo;
        this.ativo = ativo;
    }
}
