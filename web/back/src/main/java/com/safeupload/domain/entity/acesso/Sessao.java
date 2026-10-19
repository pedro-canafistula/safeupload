package com.safeupload.domain.entity.acesso;

import java.time.LocalDateTime;

import jakarta.persistence.*;

@Entity 
@Table (name = "sessoes")
public class Sessao {
    @Id 
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    @Column (name="id_sessao")
    private Integer idSessao;

    @ManyToOne (fetch = FetchType.LAZY)
    @JoinColumn (
        name = "fk_id_usuario",
        nullable = true,
        foreignKey = @ForeignKey (name = "fk_id_usuario_01")
    )
    private Usuario fkIdUsuario;

    @Column(name="ip_origem")
    private String ipOrigem;

    @Column (name="tentativa_conexao")
    private String tentativaConexao;

    @Column (name="motivo")
    private String motivo;

    @Column (name="status")
    private int status;

    @Column (name="data_hora_logon")
    private LocalDateTime dataHoraLogon;

    @Column (name="data_hora_logoff")
    private LocalDateTime dataHoraLogoff;

    protected Sessao(){}

    public Sessao(
        Usuario fkIdUsuario,
        String ipOrigem,
        String tentativaConexao,
        String motivo,
        int status,
        LocalDateTime dataHoraLogon,
        LocalDateTime dataHoraLogoff
    ) {
        this.fkIdUsuario = fkIdUsuario;
        this.ipOrigem = ipOrigem;
        this.tentativaConexao = tentativaConexao;
        this.motivo = motivo;
        this.status = status;
        this.dataHoraLogon = dataHoraLogon;
        this.dataHoraLogoff = dataHoraLogoff;
    }

    public Integer getIdSessao() {
        return idSessao;
    }

    public Usuario getFkIdUsuario() {
        return fkIdUsuario;
    }

    public String getIpOrigem() {
        return ipOrigem;
    }

    public String getTentativaConexao() {
        return tentativaConexao;
    }

    public String getMotivo() {
        return motivo;
    }

    public int getStatus() {
        return status;
    }

    public LocalDateTime getDataHoraLogon() {
        return dataHoraLogon;
    }

    public LocalDateTime getDataHoraLogoff() {
        return dataHoraLogoff;
    }
}
