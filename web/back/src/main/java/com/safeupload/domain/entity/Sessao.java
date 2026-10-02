package com.safeupload.domain.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "sessoes")
public class Sessao {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idSessao;

    // Sem @ManyToOne de propósito: mantém simples, guarda só o id.
    // Se quiser navegação objeto-a-objeto depois, troca por relacionamento JPA.
    private Long fkIdUsuario;

    @Column(length = 45)
    private String ipOrigem;

    @Column(length = 500)
    private String agenteConexao;

    @Column(nullable = false)
    private boolean statusFinal;

    @Column(length = 255)
    private String motivo;

    @Column(nullable = false)
    private LocalDateTime dataHoraLogon = LocalDateTime.now();

    private LocalDateTime dataHoraLogout;

    // --- getters e setters ---

    public Long getIdSessao() { return idSessao; }
    public void setIdSessao(Long idSessao) { this.idSessao = idSessao; }

    public Long getFkIdUsuario() { return fkIdUsuario; }
    public void setFkIdUsuario(Long fkIdUsuario) { this.fkIdUsuario = fkIdUsuario; }

    public String getIpOrigem() { return ipOrigem; }
    public void setIpOrigem(String ipOrigem) { this.ipOrigem = ipOrigem; }

    public String getAgenteConexao() { return agenteConexao; }
    public void setAgenteConexao(String agenteConexao) { this.agenteConexao = agenteConexao; }

    public boolean isStatusFinal() { return statusFinal; }
    public void setStatusFinal(boolean statusFinal) { this.statusFinal = statusFinal; }

    public String getMotivo() { return motivo; }
    public void setMotivo(String motivo) { this.motivo = motivo; }

    public LocalDateTime getDataHoraLogon() { return dataHoraLogon; }
    public void setDataHoraLogon(LocalDateTime dataHoraLogon) { this.dataHoraLogon = dataHoraLogon; }

    public LocalDateTime getDataHoraLogout() { return dataHoraLogout; }
    public void setDataHoraLogout(LocalDateTime dataHoraLogout) { this.dataHoraLogout = dataHoraLogout; }
}
