package com.safeupload.domain.entity.app;

import java.time.LocalDateTime;

import jakarta.persistence.*;

@Entity 
@Table (name="hosts")
public class Host {
    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column (name="id_host")
    private Integer idHost;

    @Column (name="ip")
    private String ip;

    @Column (name="mascara")
    private int mascara;

    @Column (name="hostname")
    private String hostname;

    @Column (name="sistema_operacional")
    private String sistemaOperacional;

    @Column (name="versao_so")
    private String versaoSO;

    @Column (name="fabricante")
    private String fabricante;

    @Column (name="modelo")
    private String modelo;

    @Column (name="mac_address")
    private String macAddress;

    @Column (name="numero_serie")
    private String numeroSerie;

    @Column(name = "visto_por_ultimo", columnDefinition = "TIMESTAMP")
    private LocalDateTime vistoPorUltimo;

    @Column(name="ativo")
    private int ativo;

    protected Host(){}

    public Host (
        String ip,
        int mascara,
        String hostname,
        String sistemaOperacional,
        String versaoSO,
        String fabricante,
        String modelo,
        String macAddress,
        String numeroSerie,
        LocalDateTime vistoPorUltimo,
        int ativo
    ) {
        this.ip = ip;
        this.mascara = mascara;
        this.hostname = hostname;
        this.sistemaOperacional = sistemaOperacional;
        this.versaoSO = versaoSO;
        this.fabricante = fabricante;
        this.modelo = modelo;
        this.macAddress = macAddress;
        this.numeroSerie = numeroSerie;
        this.vistoPorUltimo = vistoPorUltimo;
        this.ativo = ativo;
    }

    public Integer getIdHost(){
        return idHost;
    }

    public String getIp(){
        return ip;
    }

    public int getMascara(){
        return mascara;
    }

    public String getHostname(){
        return hostname;
    }

    public String getSistemaOperacional(){
        return sistemaOperacional;
    }

    public String getVersaoSO(){
        return versaoSO;
    }

    public String getFabricante(){
        return fabricante;
    }

    public String getModelo(){
        return modelo;
    }

    public String getMacAddress(){
        return macAddress;
    }

    public String getNumeroSerie(){
        return numeroSerie;
    }

    public LocalDateTime getVistoPorUltimo(){
        return vistoPorUltimo;
    }

    public int getAtivo(){
        return ativo;
    }

    public void executeHeartbeat(LocalDateTime vistoPorUltimo, int ativo) {
        this.vistoPorUltimo = vistoPorUltimo;
        this.ativo = ativo;
    }
}
