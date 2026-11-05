package com.safeupload.domain.entity.app;

import java.time.LocalDateTime;

import com.safeupload.application.dto.AgentContracts.HostRequest;

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

    @Column (name = "mascara")
    private Integer mascara;

    @Column (name="chave_publica")
    private String chavePublica;

    @Column (name="hostname")
    private String hostname;

    @Column (name="sistema_operacional")
    private String sistemaOperacional;

    @Column (name="versao_so")
    private String versaoSO;

    @Column (name="mac_address")
    private String macAddress;

    @Column(name = "visto_por_ultimo", columnDefinition = "TIMESTAMP")
    private LocalDateTime vistoPorUltimo;

    @Column(name="ativo")
    private Integer ativo;

    protected Host(){}

    public Host (
        String ip,
        Integer mascara,
        String chavePublica,
        String hostname,
        String sistemaOperacional,
        String versaoSO,
        String macAddress,
        LocalDateTime vistoPorUltimo,
        Integer ativo
    ) {
        this.ip = ip;
        this.mascara = mascara;
        this.chavePublica = chavePublica;
        this.hostname = hostname;
        this.sistemaOperacional = sistemaOperacional;
        this.versaoSO = versaoSO;
        this.macAddress = macAddress;
        this.vistoPorUltimo = vistoPorUltimo;
        this.ativo = ativo;
    }

    public Integer getIdHost(){
        return idHost;
    }

    public String getIp(){
        return ip;
    }

    public Integer getMascara(){
        return mascara;
    }

    public String getChavePublica(){
        return chavePublica;
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

    public String getMacAddress(){
        return macAddress;
    }

    public LocalDateTime getVistoPorUltimo(){
        return vistoPorUltimo;
    }

    public Integer getAtivo(){
        return ativo;
    }

    public void atualizarDados(HostRequest request, LocalDateTime agora) {

        if (request.ip() != null){
            this.ip = request.ip();
        }
        
        if (request.mascara() != null){
            this.mascara = request.mascara();
        }

        if (request.hostname() != null){
            this.hostname = request.hostname();
        }

        if (request.sistema_operacional() != null){
            this.sistemaOperacional = request.sistema_operacional();
        }

        if (request.versao_so() != null) {
            this.versaoSO = request.versao_so();
        }

        if (request.mac_address() != null){
            this.macAddress = request.mac_address();
        }

        this.vistoPorUltimo = agora;
    }
}
