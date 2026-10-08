package com.safeupload.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "politicas")
public class PoliticaEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_politica")
    private Long idPolitica;

    @Column(nullable = false, length = 255)
    private String justificativa;

    @Lob
    @Column(name = "categorias_monitoradas", nullable = false, columnDefinition = "LONGTEXT")
    private String categoriasMonitoradas;

    @Lob
    @Column(name = "extensoes_monitoradas", nullable = false, columnDefinition = "LONGTEXT")
    private String extensoesMonitoradas;

    @Lob
    @Column(name = "caminhos_de_destino", nullable = false, columnDefinition = "LONGTEXT")
    private String caminhosDeDestino;

    @Column(name = "monitorar_unidades_removiveis", nullable = false)
    private boolean monitorarUnidadesRemoviveis;
    @Column(name = "monitorar_caminhos_de_rede", nullable = false)
    private boolean monitorarCaminhosDeRede;
    @Column(name = "tamanho_maximo_arquivo_mb", nullable = false)
    private int tamanhoMaximoArquivoMb;
    @Column(name = "tempo_limite_inspecao_segundos", nullable = false)
    private int tempoLimiteInspecaoSegundos;
    @Column(name = "somente_auditoria", nullable = false)
    private boolean somenteAuditoria;
    @Column(name = "permitir_excecao", nullable = false)
    private boolean permitirExcecao;
    @Column(name = "permitir_em_caso_de_falha", nullable = false)
    private boolean permitirEmCasoDeFalha;
    @Lob
    @Column(name = "processos_ignorados", nullable = false, columnDefinition = "LONGTEXT")
    private String processosIgnorados;
    @Column(nullable = false)
    private boolean ativa;
    @Column(name = "criada_em", nullable = false)
    private LocalDateTime criadaEm;

    protected PoliticaEntity() { }

    public PoliticaEntity(String justificativa, String categoriasMonitoradas, String extensoesMonitoradas,
            String caminhosDeDestino, boolean monitorarUnidadesRemoviveis, boolean monitorarCaminhosDeRede,
            int tamanhoMaximoArquivoMb, int tempoLimiteInspecaoSegundos, boolean somenteAuditoria,
            boolean permitirExcecao, boolean permitirEmCasoDeFalha, String processosIgnorados) {
        this.justificativa = justificativa;
        this.categoriasMonitoradas = categoriasMonitoradas;
        this.extensoesMonitoradas = extensoesMonitoradas;
        this.caminhosDeDestino = caminhosDeDestino;
        this.monitorarUnidadesRemoviveis = monitorarUnidadesRemoviveis;
        this.monitorarCaminhosDeRede = monitorarCaminhosDeRede;
        this.tamanhoMaximoArquivoMb = tamanhoMaximoArquivoMb;
        this.tempoLimiteInspecaoSegundos = tempoLimiteInspecaoSegundos;
        this.somenteAuditoria = somenteAuditoria;
        this.permitirExcecao = permitirExcecao;
        this.permitirEmCasoDeFalha = permitirEmCasoDeFalha;
        this.processosIgnorados = processosIgnorados;
        this.ativa = true;
        this.criadaEm = LocalDateTime.now();
    }

    public Long getIdPolitica() { return idPolitica; }
    public String getJustificativa() { return justificativa; }
    public String getCategoriasMonitoradas() { return categoriasMonitoradas; }
    public String getExtensoesMonitoradas() { return extensoesMonitoradas; }
    public String getCaminhosDeDestino() { return caminhosDeDestino; }
    public boolean isMonitorarUnidadesRemoviveis() { return monitorarUnidadesRemoviveis; }
    public boolean isMonitorarCaminhosDeRede() { return monitorarCaminhosDeRede; }
    public int getTamanhoMaximoArquivoMb() { return tamanhoMaximoArquivoMb; }
    public int getTempoLimiteInspecaoSegundos() { return tempoLimiteInspecaoSegundos; }
    public boolean isSomenteAuditoria() { return somenteAuditoria; }
    public boolean isPermitirExcecao() { return permitirExcecao; }
    public boolean isPermitirEmCasoDeFalha() { return permitirEmCasoDeFalha; }
    public String getProcessosIgnorados() { return processosIgnorados; }
    public boolean isAtiva() { return ativa; }
    public void setAtiva(boolean ativa) { this.ativa = ativa; }
}
