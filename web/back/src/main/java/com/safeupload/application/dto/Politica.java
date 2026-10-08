package com.safeupload.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;

import java.util.List;

/** Política configurada no painel administrativo. */
public record Politica(
        @NotBlank String justificativa,
        @NotEmpty List<CategoriaMonitorada> categoriasMonitoradas,
        @NotEmpty List<String> extensoesMonitoradas,
        List<String> caminhosDeDestino,
        boolean monitorarUnidadesRemoviveis,
        boolean monitorarCaminhosDeRede,
        @Positive int tamanhoMaximoArquivoMb,
        @Positive int tempoLimiteInspecaoSegundos,
        boolean somenteAuditoria,
        boolean permitirExcecao,
        boolean permitirEmCasoDeFalha,
        List<String> processosIgnorados) {

    public enum CategoriaMonitorada {
        CPF, CNPJ, CARTAO_DE_PAGAMENTO, SENHA, SEGREDO
    }
}
